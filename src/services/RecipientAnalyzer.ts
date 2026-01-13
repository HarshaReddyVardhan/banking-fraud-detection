import { config } from '../config/config';
import { logger, fraudLogger } from '../middleware/requestLogger';
import { cacheService } from './CacheService';
import { RiskFactor, RecipientInfo, UserTransactionHistory } from '../types';
import { FraudBlocklist } from '../models/FraudBlocklist';
import crypto from 'crypto';

/**
 * Recipient Analyzer Service
 * Detects transfers to new, risky, or blocked recipients
 */
export class RecipientAnalyzer {
    private readonly newRecipientDays: number;
    private readonly trustedRecipientMinTransfers: number;
    private readonly weight: number;

    constructor() {
        this.newRecipientDays = config.analysis.recipient.newRecipientDays;
        this.trustedRecipientMinTransfers = config.analysis.recipient.trustedRecipientMinTransfers;
        this.weight = config.thresholds.recipientWeight;
    }

    /**
     * Analyze recipient risk for a transaction
     */
    async analyze(
        userId: string,
        transactionId: string,
        recipientId: string,
        recipientAccountId: string,
        userHistory: UserTransactionHistory | null,
        trustedRecipients: string[]
    ): Promise<RiskFactor> {
        const reasons: string[] = [];
        let totalScore = 0;

        try {
            // Check blocklist first
            const blocklistMatch = await this.checkBlocklist(recipientId, recipientAccountId);
            if (blocklistMatch.detected) {
                // Blocklist match is critical - immediate high score
                return {
                    method: 'RECIPIENT',
                    score: 1.0, // Maximum score for blocklist match
                    weight: this.weight,
                    contributedScore: 1.0,
                    reason: blocklistMatch.reason,
                    details: {
                        recipientId,
                        blocked: true,
                        blockReason: blocklistMatch.blockReason,
                    },
                };
            }

            // Get recipient info from cache or compute
            let recipientInfo = await cacheService.getRecipientInfo(recipientId);
            if (!recipientInfo) {
                recipientInfo = await this.computeRecipientInfo(recipientId, userHistory);
                if (recipientInfo) {
                    await cacheService.setRecipientInfo(recipientId, recipientInfo);
                }
            }

            // Check if recipient is new
            const isNewRecipient = this.checkNewRecipient(
                recipientId,
                recipientInfo,
                trustedRecipients
            );
            if (isNewRecipient.detected) {
                totalScore += isNewRecipient.score;
                reasons.push(isNewRecipient.reason);
            }

            // Check recipient risk score
            if (recipientInfo && recipientInfo.riskScore > 0.3) {
                totalScore += recipientInfo.riskScore * 0.2;
                reasons.push(`Recipient has elevated risk score (${recipientInfo.riskScore.toFixed(2)})`);
            }

            // Check if recipient account is very new
            if (recipientInfo && recipientInfo.accountAge !== undefined && recipientInfo.accountAge < 30) {
                totalScore += 0.10;
                reasons.push('Recipient account less than 30 days old');
            }

            // Check if recipient is in high-risk country
            if (recipientInfo && recipientInfo.country) {
                const highRiskCountries = ['NG', 'RU', 'VN', 'UA', 'RO'];
                if (highRiskCountries.includes(recipientInfo.country)) {
                    totalScore += 0.08;
                    reasons.push(`Recipient in high-risk region (${recipientInfo.country})`);
                }
            }

            // Check if recipient is unverified
            if (recipientInfo && !recipientInfo.isVerified) {
                totalScore += 0.05;
                reasons.push('Recipient account not verified');
            }

            // Check for first-time large transfer pattern
            if (isNewRecipient.detected && userHistory) {
                // TODO: Check if this is a pattern of sending to new recipients
                const recentNewRecipients = this.countRecentNewRecipients(userHistory);
                if (recentNewRecipients >= 3) {
                    totalScore += 0.12;
                    reasons.push(`Multiple new recipients in short time (${recentNewRecipients} in recent history)`);
                }
            }

            // Cap the total recipient score
            totalScore = Math.min(totalScore, 0.45);

            const riskFactor: RiskFactor = {
                method: 'RECIPIENT',
                score: totalScore,
                weight: this.weight,
                contributedScore: totalScore * this.weight,
                reason: reasons.length > 0
                    ? reasons.join('; ')
                    : trustedRecipients.includes(recipientId)
                        ? 'Trusted recipient'
                        : 'Normal recipient',
                details: {
                    recipientId,
                    isNew: isNewRecipient.detected,
                    isTrusted: trustedRecipients.includes(recipientId),
                    recipientRiskScore: recipientInfo?.riskScore,
                    recipientAge: recipientInfo?.accountAge,
                    isVerified: recipientInfo?.isVerified,
                },
            };

            logger.debug('Recipient analysis complete', {
                userId,
                transactionId,
                recipientId,
                score: totalScore,
            });

            return riskFactor;
        } catch (error) {
            logger.error('Recipient analysis error', { userId, transactionId, error });

            return {
                method: 'RECIPIENT',
                score: 0,
                weight: this.weight,
                contributedScore: 0,
                reason: 'Recipient analysis unavailable',
                details: { error: 'Analysis failed' },
            };
        }
    }

    /**
     * Check if recipient is in blocklist
     */
    private async checkBlocklist(
        recipientId: string,
        recipientAccountId: string
    ): Promise<{ detected: boolean; reason: string; blockReason?: string }> {
        try {
            // Check cache first
            const cachedBlock = await cacheService.isInBlocklist('RECIPIENT', recipientId);
            if (cachedBlock && cachedBlock.isActive) {
                fraudLogger.blocklistMatch('RECIPIENT', recipientId, recipientId);
                return {
                    detected: true,
                    reason: `Recipient ${recipientId} is on fraud blocklist`,
                    blockReason: cachedBlock.reason,
                };
            }

            // Check account ID in blocklist
            const cachedAccountBlock = await cacheService.isInBlocklist('ACCOUNT', recipientAccountId);
            if (cachedAccountBlock && cachedAccountBlock.isActive) {
                fraudLogger.blocklistMatch('ACCOUNT', recipientAccountId, recipientId);
                return {
                    detected: true,
                    reason: 'Recipient account is on fraud blocklist',
                    blockReason: cachedAccountBlock.reason,
                };
            }

            // Check database
            const valueHash = this.hashValue(recipientId);
            const accountHash = this.hashValue(recipientAccountId);

            const blocklistEntry = await FraudBlocklist.findOne({
                where: {
                    valueHash: [valueHash, accountHash],
                    isActive: true,
                },
            });

            if (blocklistEntry) {
                // Cache the result
                await cacheService.addToBlocklistCache({
                    id: blocklistEntry.id,
                    type: blocklistEntry.type,
                    value: blocklistEntry.value,
                    reason: blocklistEntry.reason,
                    addedBy: blocklistEntry.addedBy,
                    addedAt: blocklistEntry.createdAt.toISOString(),
                    isActive: blocklistEntry.isActive,
                });

                // Record the match
                await blocklistEntry.recordMatch();

                fraudLogger.blocklistMatch(blocklistEntry.type, recipientId, recipientId);
                return {
                    detected: true,
                    reason: `Recipient is on fraud blocklist (${blocklistEntry.type})`,
                    blockReason: blocklistEntry.reason,
                };
            }

            return { detected: false, reason: '' };
        } catch (error) {
            logger.error('Blocklist check error', { recipientId, error });
            return { detected: false, reason: '' };
        }
    }

    /**
     * Compute recipient info from user history
     */
    private async computeRecipientInfo(
        recipientId: string,
        userHistory: UserTransactionHistory | null
    ): Promise<RecipientInfo | null> {
        if (!userHistory) {
            return {
                recipientId,
                isBlocked: false,
                isNew: true,
                totalTransactions: 0,
                totalAmount: 0,
                riskScore: 0.2, // Slightly elevated for unknown
                isVerified: false,
            };
        }

        // Find transactions to this recipient
        const recipientTx = userHistory.transactions.filter(
            tx => tx.recipientId === recipientId
        );

        if (recipientTx.length === 0) {
            return {
                recipientId,
                isBlocked: false,
                isNew: true,
                totalTransactions: 0,
                totalAmount: 0,
                riskScore: 0.2,
                isVerified: false,
            };
        }

        // Calculate recipient stats
        const totalAmount = recipientTx.reduce((sum, tx) => sum + tx.amount, 0);
        const firstTx = recipientTx.reduce(
            (earliest, tx) =>
                new Date(tx.timestamp) < new Date(earliest.timestamp) ? tx : earliest,
            recipientTx[0]
        );

        // Lower risk score for established recipients
        let riskScore = 0.2;
        if (recipientTx.length >= this.trustedRecipientMinTransfers) {
            riskScore = 0.05; // Trusted
        } else if (recipientTx.length >= 2) {
            riskScore = 0.10; // Known
        }

        return {
            recipientId,
            isBlocked: false,
            isNew: false,
            firstTransactionAt: firstTx.timestamp,
            lastTransactionAt: recipientTx[recipientTx.length - 1].timestamp,
            totalTransactions: recipientTx.length,
            totalAmount,
            riskScore,
            isVerified: true, // Assume verified if has history
        };
    }

    /**
     * Check if recipient is new to the user
     */
    private checkNewRecipient(
        recipientId: string,
        recipientInfo: RecipientInfo | null,
        trustedRecipients: string[]
    ): { detected: boolean; score: number; reason: string } {
        // If in trusted list, not new
        if (trustedRecipients.includes(recipientId)) {
            return { detected: false, score: 0, reason: '' };
        }

        // If no info or marked as new
        if (!recipientInfo || recipientInfo.isNew) {
            return {
                detected: true,
                score: 0.15,
                reason: 'First transaction to this recipient',
            };
        }

        // If recipient was added recently (within 30 days)
        if (recipientInfo.firstTransactionAt) {
            const daysSinceFirst = (Date.now() - new Date(recipientInfo.firstTransactionAt).getTime()) /
                (1000 * 60 * 60 * 24);

            if (daysSinceFirst < this.newRecipientDays && recipientInfo.totalTransactions < 3) {
                return {
                    detected: true,
                    score: 0.10,
                    reason: `Recent recipient (${daysSinceFirst.toFixed(0)} days, ${recipientInfo.totalTransactions} transactions)`,
                };
            }
        }

        return { detected: false, score: 0, reason: '' };
    }

    /**
     * Count recent new recipients in user history
     */
    private countRecentNewRecipients(userHistory: UserTransactionHistory): number {
        // Get unique recipients from last 24 hours
        const oneDayAgo = Date.now() - (24 * 60 * 60 * 1000);
        const recentTx = userHistory.transactions.filter(
            tx => new Date(tx.timestamp).getTime() > oneDayAgo
        );

        const recentRecipients = new Set(recentTx.map(tx => tx.recipientId));

        // Count how many are "new" (not in earlier history)
        const olderTx = userHistory.transactions.filter(
            tx => new Date(tx.timestamp).getTime() <= oneDayAgo
        );
        const establishedRecipients = new Set(olderTx.map(tx => tx.recipientId));

        let newCount = 0;
        for (const recipient of recentRecipients) {
            if (!establishedRecipients.has(recipient)) {
                newCount++;
            }
        }

        return newCount;
    }

    /**
     * Hash value for blocklist lookup
     */
    private hashValue(value: string): string {
        return crypto.createHash('sha256').update(value).digest('hex');
    }

    /**
     * Check if recipient is trusted
     */
    isTrustedRecipient(
        recipientId: string,
        trustedRecipients: string[],
        recipientInfo: RecipientInfo | null
    ): boolean {
        if (trustedRecipients.includes(recipientId)) {
            return true;
        }

        if (recipientInfo &&
            recipientInfo.totalTransactions >= this.trustedRecipientMinTransfers &&
            !recipientInfo.isBlocked) {
            return true;
        }

        return false;
    }
}

// Export singleton
export const recipientAnalyzer = new RecipientAnalyzer();
