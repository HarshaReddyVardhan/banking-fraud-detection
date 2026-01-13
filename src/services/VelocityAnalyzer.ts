import { config } from '../config/config';
import { logger, fraudLogger } from '../middleware/requestLogger';
import { cacheService } from './CacheService';
import { RiskFactor, VelocityData } from '../types';

/**
 * Velocity Analyzer Service
 * Detects abnormal transfer frequency patterns that may indicate fraud
 */
export class VelocityAnalyzer {
    private readonly maxTransfersPerFiveMin: number;
    private readonly maxTransfersPerHour: number;
    private readonly maxTransfersPerDay: number;
    private readonly weights: {
        fiveMinute: number;
        oneHour: number;
        twentyFourHours: number;
    };

    constructor() {
        this.maxTransfersPerFiveMin = config.analysis.velocity.maxTransfersPerFiveMin;
        this.maxTransfersPerHour = config.analysis.velocity.maxTransfersPerHour;
        this.maxTransfersPerDay = config.analysis.velocity.maxTransfersPerDay;
        this.weights = config.thresholds.velocityWeights;
    }

    /**
     * Analyze velocity for a transaction
     * @returns Risk factor with velocity-based risk contribution
     */
    async analyze(
        userId: string,
        transactionId: string,
        amount: number,
        recipientId: string
    ): Promise<RiskFactor> {
        const reasons: string[] = [];
        let totalScore = 0;

        try {
            // Get current velocity data from cache
            const velocityData = await this.getVelocityData(userId);

            // Increment velocity counters for this new transaction
            await this.incrementVelocity(userId, amount);

            // Check 5-minute window
            if (velocityData.transactionsFiveMin >= this.maxTransfersPerFiveMin) {
                const severity = Math.min(
                    velocityData.transactionsFiveMin / this.maxTransfersPerFiveMin,
                    2.0
                );
                totalScore += this.weights.fiveMinute * severity;
                reasons.push(
                    `High frequency: ${velocityData.transactionsFiveMin + 1} transfers in 5 minutes (max: ${this.maxTransfersPerFiveMin})`
                );

                fraudLogger.velocityViolation(userId, transactionId, '5min', velocityData.transactionsFiveMin + 1);
            }

            // Check 1-hour window
            if (velocityData.transactionsOneHour >= this.maxTransfersPerHour) {
                const severity = Math.min(
                    velocityData.transactionsOneHour / this.maxTransfersPerHour,
                    2.0
                );
                totalScore += this.weights.oneHour * severity;
                reasons.push(
                    `High frequency: ${velocityData.transactionsOneHour + 1} transfers in 1 hour (max: ${this.maxTransfersPerHour})`
                );

                fraudLogger.velocityViolation(userId, transactionId, '1hour', velocityData.transactionsOneHour + 1);
            }

            // Check 24-hour window
            if (velocityData.transactionsTwentyFourHours >= this.maxTransfersPerDay) {
                const severity = Math.min(
                    velocityData.transactionsTwentyFourHours / this.maxTransfersPerDay,
                    2.0
                );
                totalScore += this.weights.twentyFourHours * severity;
                reasons.push(
                    `High frequency: ${velocityData.transactionsTwentyFourHours + 1} transfers in 24 hours (max: ${this.maxTransfersPerDay})`
                );

                fraudLogger.velocityViolation(userId, transactionId, '24hour', velocityData.transactionsTwentyFourHours + 1);
            }

            // Check for amount velocity spikes (10x normal in short window)
            const amountSpike = await this.checkAmountSpike(userId, velocityData, amount);
            if (amountSpike.detected) {
                totalScore += amountSpike.score;
                reasons.push(amountSpike.reason);
            }

            // Check for rapid sequential transfers to different recipients
            const rapidDiverseTransfers = await this.checkRapidDiverseTransfers(
                userId,
                recipientId,
                velocityData
            );
            if (rapidDiverseTransfers.detected) {
                totalScore += rapidDiverseTransfers.score;
                reasons.push(rapidDiverseTransfers.reason);
            }

            // Cap the total velocity score
            totalScore = Math.min(totalScore, 0.45);

            const riskFactor: RiskFactor = {
                method: 'VELOCITY',
                score: totalScore,
                weight: 1.0,
                contributedScore: totalScore,
                reason: reasons.length > 0
                    ? reasons.join('; ')
                    : 'Normal transaction velocity',
                details: {
                    transactionsFiveMin: velocityData.transactionsFiveMin + 1,
                    transactionsOneHour: velocityData.transactionsOneHour + 1,
                    transactionsTwentyFourHours: velocityData.transactionsTwentyFourHours + 1,
                    amountFiveMin: velocityData.amountFiveMin + amount,
                    amountOneHour: velocityData.amountOneHour + amount,
                    amountTwentyFourHours: velocityData.amountTwentyFourHours + amount,
                },
            };

            logger.debug('Velocity analysis complete', {
                userId,
                transactionId,
                score: totalScore,
                reasons: reasons.length,
            });

            return riskFactor;
        } catch (error) {
            logger.error('Velocity analysis error', { userId, transactionId, error });

            // Return neutral score on error
            return {
                method: 'VELOCITY',
                score: 0,
                weight: 1.0,
                contributedScore: 0,
                reason: 'Velocity analysis unavailable',
                details: { error: 'Analysis failed' },
            };
        }
    }

    /**
     * Get current velocity data for user
     */
    private async getVelocityData(userId: string): Promise<VelocityData> {
        const [fiveMin, oneHour, twentyFourHours] = await Promise.all([
            cacheService.getVelocity(userId, '5m'),
            cacheService.getVelocity(userId, '1h'),
            cacheService.getVelocity(userId, '24h'),
        ]);

        return {
            transactionsFiveMin: fiveMin.count,
            transactionsOneHour: oneHour.count,
            transactionsTwentyFourHours: twentyFourHours.count,
            amountFiveMin: fiveMin.totalAmount,
            amountOneHour: oneHour.totalAmount,
            amountTwentyFourHours: twentyFourHours.totalAmount,
            uniqueRecipientsFiveMin: 0, // TODO: Track unique recipients
            uniqueRecipientsOneHour: 0,
        };
    }

    /**
     * Increment velocity counters
     */
    private async incrementVelocity(userId: string, amount: number): Promise<void> {
        await Promise.all([
            cacheService.incrementVelocity(userId, '5m', amount),
            cacheService.incrementVelocity(userId, '1h', amount),
            cacheService.incrementVelocity(userId, '24h', amount),
        ]);
    }

    /**
     * Check for unusual amount spikes
     */
    private async checkAmountSpike(
        userId: string,
        velocityData: VelocityData,
        currentAmount: number
    ): Promise<{ detected: boolean; score: number; reason: string }> {
        const result = { detected: false, score: 0, reason: '' };

        // Check if recent amounts (5 min window) are 10x above average 24h amounts
        if (velocityData.transactionsTwentyFourHours > 0) {
            const avgDailyAmount = velocityData.amountTwentyFourHours / velocityData.transactionsTwentyFourHours;
            const recentTotalWithCurrent = velocityData.amountFiveMin + currentAmount;

            if (recentTotalWithCurrent > avgDailyAmount * 10) {
                result.detected = true;
                result.score = 0.12;
                result.reason = `Amount spike: ${recentTotalWithCurrent.toFixed(2)} in 5 minutes vs ${avgDailyAmount.toFixed(2)} average`;
            }
        }

        return result;
    }

    /**
     * Check for rapid transfers to multiple different recipients
     */
    private async checkRapidDiverseTransfers(
        userId: string,
        recipientId: string,
        velocityData: VelocityData
    ): Promise<{ detected: boolean; score: number; reason: string }> {
        const result = { detected: false, score: 0, reason: '' };

        // If high transaction count in 5 min with multiple recipients
        // This is a placeholder - would need to track unique recipients in Redis
        if (velocityData.transactionsFiveMin >= 3 && velocityData.uniqueRecipientsFiveMin >= 3) {
            result.detected = true;
            result.score = 0.10;
            result.reason = `Rapid transfers to ${velocityData.uniqueRecipientsFiveMin} different recipients`;
        }

        return result;
    }

    /**
     * Get velocity thresholds for a specific user (for whitelisted users)
     */
    getThresholdsForUser(isWhitelisted: boolean): {
        maxFiveMin: number;
        maxHour: number;
        maxDay: number;
    } {
        if (isWhitelisted) {
            // Higher thresholds for whitelisted users (merchants, financial advisors)
            return {
                maxFiveMin: this.maxTransfersPerFiveMin * 10,
                maxHour: this.maxTransfersPerHour * 10,
                maxDay: this.maxTransfersPerDay * 5,
            };
        }

        return {
            maxFiveMin: this.maxTransfersPerFiveMin,
            maxHour: this.maxTransfersPerHour,
            maxDay: this.maxTransfersPerDay,
        };
    }
}

// Export singleton
export const velocityAnalyzer = new VelocityAnalyzer();
