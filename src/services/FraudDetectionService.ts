import { config } from '../config/config';
import { logger, fraudLogger } from '../middleware/requestLogger';
import { cacheService } from './CacheService';
import { eventPublisher } from '../kafka/EventPublisher';
import { FraudAnalysis } from '../models/FraudAnalysis';
import { amountAnalyzer } from './AmountAnalyzer';
import { velocityAnalyzer } from './VelocityAnalyzer';
import { mlModelService } from './MLModelService';
import {
    TransactionCreatedEvent,
    FraudAnalysisResult,
    RiskFactor,
    AnalysisStatus,
    RiskDecision,
    ConfidenceLevel,
    MLFeatures,
    GeoLocation
} from '../types';
import { v4 as uuidv4 } from 'uuid';

import { deviceAnalyzer } from './DeviceAnalyzer';
import { geographicAnalyzer } from './GeographicAnalyzer';
import { recipientAnalyzer } from './RecipientAnalyzer';
import { timeAnalyzer } from './TimeAnalyzer';

export class FraudDetectionService {

    /**
     * Process a new transaction event
     */
    async processTransaction(event: TransactionCreatedEvent): Promise<void> {
        const { payload: transaction, correlationId } = event;
        const startTime = Date.now();
        const analysisId = uuidv4();

        logger.info('Starting fraud analysis', {
            transactionId: transaction.transactionId,
            userId: transaction.userId,
            amount: transaction.amount
        });

        try {
            // 1. Idempotency Check
            const cachedResult = await cacheService.getCachedAnalysis(transaction.transactionId);
            if (cachedResult) {
                logger.info('Transaction already analyzed (idempotency hit)', { transactionId: transaction.transactionId });
                return;
            }

            // 2. Load Context Data
            const userHistory = await cacheService.getUserHistory(transaction.userId);

            // 3. Run Rule-Based Analyzers in Parallel
            const riskFactors: RiskFactor[] = [];

            // Gather auxiliary data
            // In a full implementation, these would fetch from user profile service or DB
            const knownDevices: string[] = [];
            const knownCountries: string[] = [];
            const trustedRecipients: string[] = [];

            // Build time preferences
            const preferredHours = timeAnalyzer.buildPreferredHours(userHistory);
            const preferredDays = timeAnalyzer.buildPreferredDays(userHistory);

            // Construct GeoLocation object safely
            const currentLocation: GeoLocation = {
                ip: transaction.geographic?.ip,
                country: transaction.geographic?.country || null,
                city: transaction.geographic?.city || null,
                latitude: transaction.geographic?.latitude || null,
                longitude: transaction.geographic?.longitude || null
            };

            const results = await Promise.allSettled([
                this.safeAnalyze(() => amountAnalyzer.analyze(
                    transaction.userId,
                    transaction.transactionId,
                    transaction.amount,
                    transaction.currency,
                    userHistory
                ), 'AMOUNT'),

                this.safeAnalyze(() => velocityAnalyzer.analyze(
                    transaction.userId,
                    transaction.transactionId,
                    transaction.amount,
                    transaction.recipientId
                ), 'VELOCITY'),

                this.safeAnalyze(() => deviceAnalyzer.analyze(
                    transaction.userId,
                    transaction.transactionId,
                    transaction.device?.fingerprint,
                    transaction.device?.userAgent,
                    transaction.device?.deviceId,
                    knownDevices,
                    userHistory
                ), 'DEVICE'),

                this.safeAnalyze(() => geographicAnalyzer.analyze(
                    transaction.userId,
                    transaction.transactionId,
                    currentLocation,
                    userHistory,
                    knownCountries
                ), 'GEOGRAPHIC'),

                this.safeAnalyze(() => recipientAnalyzer.analyze(
                    transaction.userId,
                    transaction.transactionId,
                    transaction.recipientId,
                    transaction.destinationAccountId,
                    userHistory,
                    trustedRecipients
                ), 'RECIPIENT'),

                this.safeAnalyze(() => timeAnalyzer.analyze(
                    transaction.userId,
                    transaction.transactionId,
                    new Date(transaction.timestamp),
                    userHistory,
                    preferredHours,
                    preferredDays,
                    undefined // Timezone
                ), 'TIME')
            ]);

            // Collect risk factors
            results.forEach(result => {
                if (result.status === 'fulfilled' && result.value) {
                    riskFactors.push(result.value);
                }
            });

            // 4. ML Model Prediction
            const mlFeatures = this.constructMLFeatures(transaction, riskFactors, userHistory);

            // Ensure model loaded
            if (!mlModelService.isModelReady()) {
                await mlModelService.loadModel();
            }

            const mlResult = await mlModelService.predict(transaction.transactionId, mlFeatures);

            if (mlResult) {
                riskFactors.push({
                    method: 'ML_MODEL',
                    score: mlResult.score,
                    weight: 0.3,
                    contributedScore: mlResult.score * 0.3,
                    reason: mlResult.score > 0.7 ? 'ML Model detected high risk pattern' : 'ML Model risk score',
                    details: { confidence: mlResult.confidence, modelVersion: mlResult.modelVersion }
                });
            }

            // 5. Aggregate Scores and Make Decision
            const finalResult = this.calculateFinalDecision(
                analysisId,
                transaction,
                riskFactors,
                mlResult?.modelVersion || 'unknown',
                correlationId
            );

            // 6. Persist Result
            await this.saveAnalysis(finalResult);

            // 7. Publish Event
            await this.publishResult(finalResult, correlationId);

            // 8. Cache Result
            await cacheService.cacheAnalysis(transaction.transactionId, {
                decision: finalResult.decision,
                score: finalResult.score,
                timestamp: finalResult.timestamp
            });

            const duration = Date.now() - startTime;
            fraudLogger.analysisCompleted(
                transaction.transactionId,
                transaction.userId,
                finalResult.score,
                finalResult.decision,
                finalResult.analysisTimeMs = duration, // Update analysis time
                correlationId
            );

        } catch (error) {
            logger.error('Critical error in fraud detection pipeline', {
                transactionId: transaction.transactionId,
                error
            });
            // Should probably propagate error for Kafka retry if retryable
            throw error;
        }
    }

    private async safeAnalyze(
        analyzerCall: () => Promise<RiskFactor>,
        methodName: string
    ): Promise<RiskFactor | null> {
        try {
            return await analyzerCall();
        } catch (error) {
            logger.error(`Analyzer failed: ${methodName}`, { error });
            return null;
        }
    }

    private constructMLFeatures(transaction: any, riskFactors: RiskFactor[], userHistory: any): MLFeatures {
        const velocityFactor = riskFactors.find(r => r.method === 'VELOCITY');

        return {
            txCountFiveMin: velocityFactor?.details?.transactionsFiveMin as number || 0,
            txCountOneHour: velocityFactor?.details?.transactionsOneHour as number || 0,
            txCountTwentyFourHours: velocityFactor?.details?.transactionsTwentyFourHours as number || 0,

            amount: transaction.amount,
            amountFiveMin: velocityFactor?.details?.amountFiveMin as number || transaction.amount,
            amountOneHour: velocityFactor?.details?.amountOneHour as number || transaction.amount,
            amountTwentyFourHours: velocityFactor?.details?.amountTwentyFourHours as number || transaction.amount,

            // Simplified Mapping for defaults
            amountRatioToAvg: 1,
            amountRatioToMax: 1,
            amountZScore: 0,
            isNewCountry: 0,
            distanceFromLastTx: 0,
            impossibleTravel: 0,
            hourOfDay: new Date(transaction.timestamp).getHours(),
            dayOfWeek: new Date(transaction.timestamp).getDay(),
            isUnusualHour: 0,
            timeSinceLastTx: 0,
            isNewRecipient: 0,
            recipientRiskScore: 0,
            recipientTxCount: 0,
            isNewDevice: 0,
            deviceTrustScore: 1,
            accountAge: 365,
            totalTxCount: userHistory?.statistics?.totalTransactions || 0,
            avgTxAmount: userHistory?.statistics?.averageAmount || 0,
            previousFraudFlags: 0
        };
    }

    private calculateFinalDecision(
        analysisId: string,
        transaction: any,
        riskFactors: RiskFactor[],
        modelVersion: string,
        correlationId?: string
    ): FraudAnalysisResult {
        let totalScore = 0;

        riskFactors.forEach(factor => {
            totalScore += factor.contributedScore;
        });

        // Cap at 1.0
        let finalScore = Math.min(totalScore, 1.0);

        let decision: RiskDecision = 'APPROVE';
        let requiresManualReview = finalScore >= config.thresholds.suspiciousMin;

        if (finalScore >= config.thresholds.rejectMin) {
            decision = 'REJECT';
        } else if (requiresManualReview) {
            decision = 'SUSPICIOUS';
        }

        return {
            id: analysisId, // Include ID
            transactionId: transaction.transactionId,
            userId: transaction.userId,
            score: finalScore,
            decision,
            confidence: 'HIGH',
            status: 'COMPLETED',
            riskFactors,
            modelVersion,
            analysisTimeMs: 0,
            timestamp: new Date().toISOString(),
            requiresManualReview,
            metadata: {}
        } as FraudAnalysisResult; // Cast if necessary
    }

    private async saveAnalysis(result: FraudAnalysisResult): Promise<void> {
        try {
            // Use specific create call or cast to any to avoid TS errors with strict Model types
            // result doesn't have all fields like 'id' if it generated by DB, but here we provide it (analysisId)
            await (FraudAnalysis as any).create({
                id: (result as any).id, // passed in
                transactionId: result.transactionId,
                userId: result.userId,
                score: result.score,
                decision: result.decision,
                confidence: result.confidence,
                status: result.status,
                riskFactors: result.riskFactors,
                modelVersion: result.modelVersion,
                analysisTimeMs: result.analysisTimeMs,
                requiresManualReview: result.requiresManualReview
            });
        } catch (error) {
            logger.error('Failed to save analysis to DB', { transactionId: result.transactionId, error });
        }
    }

    private async publishResult(result: FraudAnalysisResult, correlationId?: string): Promise<void> {
        // ... (Logic remains same)
        if (result.decision === 'REJECT') {
            await eventPublisher.publishFraudSuspected(result, correlationId);
        } else if (result.decision === 'SUSPICIOUS' || result.requiresManualReview) {
            await eventPublisher.publishFraudSuspected(result, correlationId);
            await eventPublisher.publishManualReviewRequired({
                analysisId: (result as any).id || uuidv4(),
                transactionId: result.transactionId,
                userId: result.userId,
                fraudScore: result.score,
                riskFactors: result.riskFactors,
                transactionDetails: {
                    amount: 0,
                    currency: 'USD',
                    recipientId: 'unknown'
                },
                userHistory: {
                    previousTransactionCount: 0,
                    averageTransactionAmount: 0,
                    accountAge: 0,
                    previousFraudFlags: 0
                },
                priority: result.score > 0.8 ? 'HIGH' : 'MEDIUM',
                createdAt: new Date().toISOString()
            }, correlationId);
        } else {
            await eventPublisher.publishAnalysisComplete(result, correlationId);
        }
    }
}

export const fraudDetectionService = new FraudDetectionService();
