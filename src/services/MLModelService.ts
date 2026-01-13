import fs from 'fs';
import path from 'path';
import crypto from 'crypto';
import { config } from '../config/config';
import { logger, fraudLogger } from '../middleware/requestLogger';
import { MLFeatures } from '../types';
import { ModelLoadError } from '../middleware/errorHandler';

/**
 * ML Model Type for inference
 */
interface MLModel {
    version: string;
    predict: (features: number[]) => Promise<{ score: number; confidence: number }>;
    getFeatureNames: () => string[];
}

/**
 * Simple rule-based model as fallback
 */
class RuleBasedModel implements MLModel {
    version = 'rule-based-v1';

    async predict(features: number[]): Promise<{ score: number; confidence: number }> {
        // Feature indices (based on MLFeatures order)
        const velocity5m = features[0] || 0;
        const velocity1h = features[1] || 0;
        const amountRatio = features[7] || 0;
        const impossibleTravel = features[12] || 0;
        const isNewRecipient = features[15] || 0;
        const isNewDevice = features[18] || 0;
        const prevFraudFlags = features[23] || 0;

        let score = 0;

        // Velocity rules
        if (velocity5m > 3) score += 0.15;
        if (velocity1h > 10) score += 0.10;

        // Amount rules
        if (amountRatio > 5) score += 0.20;

        // Geographic rules
        if (impossibleTravel > 0) score += 0.30;

        // Recipient rules
        if (isNewRecipient > 0) score += 0.10;

        // Device rules
        if (isNewDevice > 0) score += 0.10;

        // Previous fraud
        if (prevFraudFlags > 0) score += 0.15 * Math.min(prevFraudFlags, 3);

        // Cap at 0.95
        score = Math.min(score, 0.95);

        return {
            score,
            confidence: 0.7, // Lower confidence for rule-based
        };
    }

    getFeatureNames(): string[] {
        return [
            'txCountFiveMin', 'txCountOneHour', 'txCountTwentyFourHours',
            'amountFiveMin', 'amountOneHour', 'amountTwentyFourHours',
            'amount', 'amountRatioToAvg', 'amountRatioToMax', 'amountZScore',
            'isNewCountry', 'distanceFromLastTx', 'impossibleTravel',
            'hourOfDay', 'dayOfWeek', 'isUnusualHour', 'timeSinceLastTx',
            'isNewRecipient', 'recipientRiskScore', 'recipientTxCount',
            'isNewDevice', 'deviceTrustScore',
            'accountAge', 'totalTxCount', 'avgTxAmount', 'previousFraudFlags',
        ];
    }
}

/**
 * ML Model Service
 * Manages ML model loading, inference, and fallback
 */
export class MLModelService {
    private model: MLModel | null = null;
    private fallbackModel: MLModel;
    private modelVersion: string = '';
    private isLoaded: boolean = false;
    private loadedAt: Date | null = null;
    private inferenceCount: number = 0;
    private totalInferenceTimeMs: number = 0;

    constructor() {
        this.fallbackModel = new RuleBasedModel();
    }

    /**
     * Load the ML model
     */
    async loadModel(): Promise<void> {
        const startTime = Date.now();

        try {
            const modelPath = config.ml.modelPath;

            // Check if model file exists
            if (!fs.existsSync(modelPath)) {
                logger.warn('ML model file not found, using rule-based fallback', { modelPath });
                this.model = this.fallbackModel;
                this.modelVersion = this.fallbackModel.version;
                this.isLoaded = true;
                this.loadedAt = new Date();
                return;
            }

            // Validate model hash if configured
            if (config.ml.modelHashValidation && config.ml.expectedModelHash) {
                const isValid = await this.validateModelHash(modelPath);
                if (!isValid) {
                    throw new ModelLoadError('Model hash validation failed - possible tampering');
                }
            }

            // For now, use rule-based model as we don't have actual ONNX model
            // In production, this would load ONNX model using onnxruntime-node
            // or TensorFlow.js model
            logger.info('Loading ML model (using rule-based for demo)', { modelPath });

            // Simulate model loading
            this.model = this.fallbackModel;
            this.modelVersion = config.ml.modelVersion;
            this.isLoaded = true;
            this.loadedAt = new Date();

            const loadTime = Date.now() - startTime;
            fraudLogger.mlModelLoaded(this.modelVersion, loadTime);

            logger.info('ML model loaded successfully', {
                version: this.modelVersion,
                loadTimeMs: loadTime,
            });
        } catch (error) {
            logger.error('Failed to load ML model', { error });

            // Try fallback model
            try {
                if (config.ml.fallbackModelPath && fs.existsSync(config.ml.fallbackModelPath)) {
                    logger.info('Attempting to load fallback model');
                    this.model = this.fallbackModel; // Would load actual fallback model
                    this.modelVersion = 'fallback-' + this.fallbackModel.version;
                } else {
                    this.model = this.fallbackModel;
                    this.modelVersion = this.fallbackModel.version;
                }

                this.isLoaded = true;
                this.loadedAt = new Date();

                logger.warn('Using fallback model after primary failed', {
                    fallbackVersion: this.modelVersion,
                });
            } catch (fallbackError) {
                fraudLogger.mlModelError(config.ml.modelVersion, fallbackError);
                throw new ModelLoadError('Both primary and fallback models failed to load');
            }
        }
    }

    /**
     * Run inference on transaction features
     */
    async predict(
        transactionId: string,
        features: MLFeatures
    ): Promise<{ score: number; confidence: number; modelVersion: string; inferenceTimeMs: number }> {
        if (!this.isLoaded || !this.model) {
            throw new Error('Model not loaded. Call loadModel() first.');
        }

        const startTime = Date.now();

        try {
            // Convert features to array in expected order
            const featureArray = this.featuresToArray(features);

            // Run prediction with timeout
            const prediction = await this.runWithTimeout(
                this.model.predict(featureArray),
                config.ml.inferenceTimeoutMs
            );

            const inferenceTimeMs = Date.now() - startTime;

            // Track metrics
            this.inferenceCount++;
            this.totalInferenceTimeMs += inferenceTimeMs;

            fraudLogger.mlInference(transactionId, prediction.score, inferenceTimeMs);

            return {
                score: prediction.score,
                confidence: prediction.confidence,
                modelVersion: this.modelVersion,
                inferenceTimeMs,
            };
        } catch (error) {
            logger.error('ML inference error', { transactionId, error });

            // Return neutral prediction on error
            return {
                score: 0.5, // Neutral - will trigger manual review
                confidence: 0.1,
                modelVersion: this.modelVersion + '-error',
                inferenceTimeMs: Date.now() - startTime,
            };
        }
    }

    /**
     * Convert MLFeatures to array
     */
    private featuresToArray(features: MLFeatures): number[] {
        return [
            features.txCountFiveMin,
            features.txCountOneHour,
            features.txCountTwentyFourHours,
            features.amountFiveMin,
            features.amountOneHour,
            features.amountTwentyFourHours,
            features.amount,
            features.amountRatioToAvg,
            features.amountRatioToMax,
            features.amountZScore,
            features.isNewCountry,
            features.distanceFromLastTx,
            features.impossibleTravel,
            features.hourOfDay,
            features.dayOfWeek,
            features.isUnusualHour,
            features.timeSinceLastTx,
            features.isNewRecipient,
            features.recipientRiskScore,
            features.recipientTxCount,
            features.isNewDevice,
            features.deviceTrustScore,
            features.accountAge,
            features.totalTxCount,
            features.avgTxAmount,
            features.previousFraudFlags,
        ];
    }

    /**
     * Run promise with timeout
     */
    private async runWithTimeout<T>(
        promise: Promise<T>,
        timeoutMs: number
    ): Promise<T> {
        return Promise.race([
            promise,
            new Promise<T>((_, reject) =>
                setTimeout(() => reject(new Error('Inference timeout')), timeoutMs)
            ),
        ]);
    }

    /**
     * Validate model file hash
     */
    private async validateModelHash(modelPath: string): Promise<boolean> {
        try {
            const fileBuffer = fs.readFileSync(modelPath);
            const hash = crypto.createHash('sha256').update(fileBuffer).digest('hex');

            if (hash !== config.ml.expectedModelHash) {
                logger.error('Model hash mismatch', {
                    expected: config.ml.expectedModelHash,
                    actual: hash,
                });
                return false;
            }

            return true;
        } catch (error) {
            logger.error('Failed to validate model hash', { error });
            return false;
        }
    }

    /**
     * Get model status
     */
    getStatus(): {
        isLoaded: boolean;
        version: string;
        loadedAt: Date | null;
        inferenceCount: number;
        avgInferenceTimeMs: number;
    } {
        return {
            isLoaded: this.isLoaded,
            version: this.modelVersion,
            loadedAt: this.loadedAt,
            inferenceCount: this.inferenceCount,
            avgInferenceTimeMs: this.inferenceCount > 0
                ? this.totalInferenceTimeMs / this.inferenceCount
                : 0,
        };
    }

    /**
     * Check if model is ready
     */
    isModelReady(): boolean {
        return this.isLoaded && this.model !== null;
    }

    /**
     * Get current model version
     */
    getModelVersion(): string {
        return this.modelVersion;
    }

    /**
     * Reload model (for model updates)
     */
    async reloadModel(): Promise<void> {
        logger.info('Reloading ML model');
        this.isLoaded = false;
        this.model = null;
        await this.loadModel();
    }

    /**
     * Build ML features from transaction and analysis data
     */
    buildFeatures(
        amount: number,
        velocityData: { count5m: number; count1h: number; count24h: number; amount5m: number; amount1h: number; amount24h: number },
        amountStats: { avg: number; max: number; stdDev: number },
        geoData: { isNewCountry: boolean; distance: number; impossibleTravel: boolean },
        timeData: { hour: number; day: number; isUnusual: boolean; timeSinceLast: number },
        recipientData: { isNew: boolean; riskScore: number; txCount: number },
        deviceData: { isNew: boolean; trustScore: number },
        userProfile: { accountAge: number; totalTxCount: number; avgAmount: number; fraudFlags: number }
    ): MLFeatures {
        return {
            txCountFiveMin: velocityData.count5m,
            txCountOneHour: velocityData.count1h,
            txCountTwentyFourHours: velocityData.count24h,
            amountFiveMin: velocityData.amount5m,
            amountOneHour: velocityData.amount1h,
            amountTwentyFourHours: velocityData.amount24h,
            amount,
            amountRatioToAvg: amountStats.avg > 0 ? amount / amountStats.avg : 1,
            amountRatioToMax: amountStats.max > 0 ? amount / amountStats.max : 1,
            amountZScore: amountStats.stdDev > 0 ? (amount - amountStats.avg) / amountStats.stdDev : 0,
            isNewCountry: geoData.isNewCountry ? 1 : 0,
            distanceFromLastTx: geoData.distance,
            impossibleTravel: geoData.impossibleTravel ? 1 : 0,
            hourOfDay: timeData.hour,
            dayOfWeek: timeData.day,
            isUnusualHour: timeData.isUnusual ? 1 : 0,
            timeSinceLastTx: timeData.timeSinceLast,
            isNewRecipient: recipientData.isNew ? 1 : 0,
            recipientRiskScore: recipientData.riskScore,
            recipientTxCount: recipientData.txCount,
            isNewDevice: deviceData.isNew ? 1 : 0,
            deviceTrustScore: deviceData.trustScore,
            accountAge: userProfile.accountAge,
            totalTxCount: userProfile.totalTxCount,
            avgTxAmount: userProfile.avgAmount,
            previousFraudFlags: userProfile.fraudFlags,
        };
    }
}

// Export singleton
export const mlModelService = new MLModelService();
