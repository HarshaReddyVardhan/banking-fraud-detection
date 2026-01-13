import { config } from '../config/config';
import { logger } from '../middleware/requestLogger';
import { RiskFactor, UserTransactionHistory } from '../types';

/**
 * Amount Analyzer Service
 * Detects unusually large or anomalous transaction amounts
 */
export class AmountAnalyzer {
    private readonly unusualMultiplier: number;
    private readonly largeTransferMin: number;
    private readonly weight: number;

    constructor() {
        this.unusualMultiplier = config.analysis.amount.unusualMultiplier;
        this.largeTransferMin = config.analysis.amount.largeTransferMin;
        this.weight = config.thresholds.amountWeight;
    }

    /**
     * Analyze amount risk for a transaction
     */
    async analyze(
        userId: string,
        transactionId: string,
        amount: number,
        currency: string,
        userHistory: UserTransactionHistory | null
    ): Promise<RiskFactor> {
        const reasons: string[] = [];
        let totalScore = 0;

        try {
            // Get user's transaction statistics
            const stats = userHistory?.statistics || this.getDefaultStats();

            // Check for unusually large amount compared to user's history
            const unusualAmount = this.checkUnusualAmount(amount, stats);
            if (unusualAmount.detected) {
                totalScore += unusualAmount.score;
                reasons.push(unusualAmount.reason);
            }

            // Check for amount larger than max historical
            const exceedsMax = this.checkExceedsMax(amount, stats);
            if (exceedsMax.detected) {
                totalScore += exceedsMax.score;
                reasons.push(exceedsMax.reason);
            }

            // Check for large absolute amount
            const absoluteLarge = this.checkAbsoluteLarge(amount);
            if (absoluteLarge.detected) {
                totalScore += absoluteLarge.score;
                reasons.push(absoluteLarge.reason);
            }

            // Check for round number amounts (common in fraud)
            const roundNumber = this.checkRoundNumber(amount);
            if (roundNumber.detected) {
                totalScore += roundNumber.score;
                reasons.push(roundNumber.reason);
            }

            // Check for amount just below reporting threshold
            const belowThreshold = this.checkBelowReportingThreshold(amount);
            if (belowThreshold.detected) {
                totalScore += belowThreshold.score;
                reasons.push(belowThreshold.reason);
            }

            // Check z-score (statistical anomaly)
            if (stats.standardDeviation > 0) {
                const zScore = this.checkZScore(amount, stats);
                if (zScore.detected) {
                    totalScore += zScore.score;
                    reasons.push(zScore.reason);
                }
            }

            // New account large transfer
            if (this.isNewAccount(stats) && amount > 1000) {
                const newAccountLarge = {
                    detected: true,
                    score: 0.08,
                    reason: `Large transfer (${amount}) from account less than 30 days old`,
                };
                totalScore += newAccountLarge.score;
                reasons.push(newAccountLarge.reason);
            }

            // Cap the total amount score
            totalScore = Math.min(totalScore, 0.40);

            const riskFactor: RiskFactor = {
                method: 'AMOUNT',
                score: totalScore,
                weight: this.weight,
                contributedScore: totalScore * this.weight,
                reason: reasons.length > 0
                    ? reasons.join('; ')
                    : 'Normal transaction amount',
                details: {
                    amount,
                    currency,
                    userAverage: stats.averageAmount,
                    userMax: stats.maxAmount,
                    userStdDev: stats.standardDeviation,
                    totalTransactions: stats.totalTransactions,
                },
            };

            logger.debug('Amount analysis complete', {
                userId,
                transactionId,
                amount,
                score: totalScore,
            });

            return riskFactor;
        } catch (error) {
            logger.error('Amount analysis error', { userId, transactionId, error });

            return {
                method: 'AMOUNT',
                score: 0,
                weight: this.weight,
                contributedScore: 0,
                reason: 'Amount analysis unavailable',
                details: { error: 'Analysis failed' },
            };
        }
    }

    /**
     * Get default statistics for new users
     */
    private getDefaultStats() {
        return {
            totalTransactions: 0,
            averageAmount: 0,
            maxAmount: 0,
            minAmount: 0,
            standardDeviation: 0,
            uniqueRecipients: 0,
            uniqueCountries: 0,
            uniqueDevices: 0,
            accountCreatedAt: new Date().toISOString(),
        };
    }

    /**
     * Check if amount is unusual compared to user's average
     */
    private checkUnusualAmount(
        amount: number,
        stats: { averageAmount: number; totalTransactions: number }
    ): { detected: boolean; score: number; reason: string } {
        if (stats.totalTransactions < 5 || stats.averageAmount === 0) {
            return { detected: false, score: 0, reason: '' };
        }

        const ratio = amount / stats.averageAmount;

        if (ratio >= this.unusualMultiplier * 2) {
            return {
                detected: true,
                score: 0.20,
                reason: `Amount ${ratio.toFixed(1)}x higher than user average (${stats.averageAmount.toFixed(2)})`,
            };
        }

        if (ratio >= this.unusualMultiplier) {
            return {
                detected: true,
                score: 0.12,
                reason: `Amount ${ratio.toFixed(1)}x higher than user average (${stats.averageAmount.toFixed(2)})`,
            };
        }

        return { detected: false, score: 0, reason: '' };
    }

    /**
     * Check if amount exceeds user's historical max
     */
    private checkExceedsMax(
        amount: number,
        stats: { maxAmount: number; totalTransactions: number }
    ): { detected: boolean; score: number; reason: string } {
        if (stats.totalTransactions < 3 || stats.maxAmount === 0) {
            return { detected: false, score: 0, reason: '' };
        }

        if (amount > stats.maxAmount * 2) {
            return {
                detected: true,
                score: 0.15,
                reason: `Amount exceeds 2x user's historical max (${stats.maxAmount.toFixed(2)})`,
            };
        }

        if (amount > stats.maxAmount * 1.5) {
            return {
                detected: true,
                score: 0.08,
                reason: `Amount exceeds 1.5x user's historical max (${stats.maxAmount.toFixed(2)})`,
            };
        }

        return { detected: false, score: 0, reason: '' };
    }

    /**
     * Check for absolutely large amount
     */
    private checkAbsoluteLarge(
        amount: number
    ): { detected: boolean; score: number; reason: string } {
        if (amount >= this.largeTransferMin * 10) {
            return {
                detected: true,
                score: 0.12,
                reason: `Very large transfer amount (${amount.toFixed(2)})`,
            };
        }

        if (amount >= this.largeTransferMin * 5) {
            return {
                detected: true,
                score: 0.08,
                reason: `Large transfer amount (${amount.toFixed(2)})`,
            };
        }

        if (amount >= this.largeTransferMin) {
            return {
                detected: true,
                score: 0.04,
                reason: `Significant transfer amount (${amount.toFixed(2)})`,
            };
        }

        return { detected: false, score: 0, reason: '' };
    }

    /**
     * Check for round number amounts (common fraud pattern)
     */
    private checkRoundNumber(
        amount: number
    ): { detected: boolean; score: number; reason: string } {
        // Check for very round numbers like 1000, 5000, 10000
        const roundThresholds = [1000, 2000, 5000, 10000, 20000, 50000, 100000];

        for (const threshold of roundThresholds) {
            if (amount === threshold) {
                return {
                    detected: true,
                    score: 0.05,
                    reason: `Perfectly round amount (${amount}) - common in fraud`,
                };
            }
        }

        // Check for amounts ending in 00
        if (amount >= 500 && amount % 100 === 0) {
            return {
                detected: true,
                score: 0.03,
                reason: 'Round number amount',
            };
        }

        return { detected: false, score: 0, reason: '' };
    }

    /**
     * Check for amounts just below reporting thresholds
     * Banks must report transactions over $10,000 (CTR)
     */
    private checkBelowReportingThreshold(
        amount: number
    ): { detected: boolean; score: number; reason: string } {
        // CTR threshold is $10,000
        // Suspicious if just under (structuring/smurfing pattern)
        if (amount >= 9000 && amount < 10000) {
            return {
                detected: true,
                score: 0.15,
                reason: 'Amount just below $10,000 reporting threshold (potential structuring)',
            };
        }

        // Some banks have additional thresholds at $3,000 and $5,000
        if (amount >= 4800 && amount < 5000) {
            return {
                detected: true,
                score: 0.08,
                reason: 'Amount just below common threshold',
            };
        }

        if (amount >= 2900 && amount < 3000) {
            return {
                detected: true,
                score: 0.05,
                reason: 'Amount just below common threshold',
            };
        }

        return { detected: false, score: 0, reason: '' };
    }

    /**
     * Check statistical z-score anomaly
     */
    private checkZScore(
        amount: number,
        stats: { averageAmount: number; standardDeviation: number }
    ): { detected: boolean; score: number; reason: string } {
        const zScore = (amount - stats.averageAmount) / stats.standardDeviation;

        if (zScore >= 4) {
            return {
                detected: true,
                score: 0.18,
                reason: `Statistical anomaly: z-score of ${zScore.toFixed(2)} (4+ std devs from mean)`,
            };
        }

        if (zScore >= 3) {
            return {
                detected: true,
                score: 0.12,
                reason: `Statistical anomaly: z-score of ${zScore.toFixed(2)} (3+ std devs from mean)`,
            };
        }

        if (zScore >= 2) {
            return {
                detected: true,
                score: 0.06,
                reason: `Elevated amount: z-score of ${zScore.toFixed(2)} (2+ std devs from mean)`,
            };
        }

        return { detected: false, score: 0, reason: '' };
    }

    /**
     * Check if account is new (less than 30 days old)
     */
    private isNewAccount(stats: { accountCreatedAt: string }): boolean {
        const createdAt = new Date(stats.accountCreatedAt);
        const daysSinceCreation = (Date.now() - createdAt.getTime()) / (1000 * 60 * 60 * 24);
        return daysSinceCreation < 30;
    }

    /**
     * Calculate amount z-score for ML features
     */
    calculateZScore(
        amount: number,
        average: number,
        stdDev: number
    ): number {
        if (stdDev === 0) return 0;
        return (amount - average) / stdDev;
    }
}

// Export singleton
export const amountAnalyzer = new AmountAnalyzer();
