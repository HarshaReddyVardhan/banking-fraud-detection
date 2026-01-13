import { config } from '../config/config';
import { logger } from '../middleware/requestLogger';
import { RiskFactor, UserTransactionHistory } from '../types';

/**
 * Time Analyzer Service
 * Detects transfers at unusual times based on user's historical patterns
 */
export class TimeAnalyzer {
    private readonly weight: number;

    constructor() {
        this.weight = config.thresholds.timeWeight;
    }

    /**
     * Analyze time-based risk for a transaction
     */
    async analyze(
        userId: string,
        transactionId: string,
        timestamp: Date,
        userHistory: UserTransactionHistory | null,
        preferredHours: number[],
        preferredDays: number[],
        userTimezone?: string
    ): Promise<RiskFactor> {
        const reasons: string[] = [];
        let totalScore = 0;

        try {
            const hour = timestamp.getHours();
            const day = timestamp.getDay(); // 0 = Sunday

            // Check for unusual hour based on user's patterns
            const unusualHour = this.checkUnusualHour(hour, preferredHours, userHistory);
            if (unusualHour.detected) {
                totalScore += unusualHour.score;
                reasons.push(unusualHour.reason);
            }

            // Check for unusual day
            const unusualDay = this.checkUnusualDay(day, preferredDays, userHistory);
            if (unusualDay.detected) {
                totalScore += unusualDay.score;
                reasons.push(unusualDay.reason);
            }

            // Check for late night/early morning (globally suspicious)
            const lateNight = this.checkLateNight(hour);
            if (lateNight.detected) {
                totalScore += lateNight.score;
                reasons.push(lateNight.reason);
            }

            // Check for weekend if user never transacts on weekends
            const weekendCheck = this.checkWeekendPattern(day, userHistory);
            if (weekendCheck.detected) {
                totalScore += weekendCheck.score;
                reasons.push(weekendCheck.reason);
            }

            // Check for holiday (simplified - would use holiday API)
            const holidayCheck = this.checkHoliday(timestamp);
            if (holidayCheck.detected) {
                totalScore += holidayCheck.score;
                reasons.push(holidayCheck.reason);
            }

            // Check for burst of activity at unusual time
            const burstCheck = this.checkActivityBurst(hour, userHistory);
            if (burstCheck.detected) {
                totalScore += burstCheck.score;
                reasons.push(burstCheck.reason);
            }

            // Cap the total time score
            totalScore = Math.min(totalScore, 0.25);

            const riskFactor: RiskFactor = {
                method: 'TIME',
                score: totalScore,
                weight: this.weight,
                contributedScore: totalScore * this.weight,
                reason: reasons.length > 0
                    ? reasons.join('; ')
                    : 'Normal transaction time',
                details: {
                    hour,
                    day,
                    dayOfWeek: this.getDayName(day),
                    preferredHours: preferredHours.length > 0 ? preferredHours : 'not established',
                    preferredDays: preferredDays.length > 0 ? preferredDays : 'not established',
                    isWeekend: day === 0 || day === 6,
                },
            };

            logger.debug('Time analysis complete', {
                userId,
                transactionId,
                hour,
                day: this.getDayName(day),
                score: totalScore,
            });

            return riskFactor;
        } catch (error) {
            logger.error('Time analysis error', { userId, transactionId, error });

            return {
                method: 'TIME',
                score: 0,
                weight: this.weight,
                contributedScore: 0,
                reason: 'Time analysis unavailable',
                details: { error: 'Analysis failed' },
            };
        }
    }

    /**
     * Check if hour is unusual for user
     */
    private checkUnusualHour(
        hour: number,
        preferredHours: number[],
        userHistory: UserTransactionHistory | null
    ): { detected: boolean; score: number; reason: string } {
        // If no preferred hours established, use global patterns
        if (preferredHours.length === 0) {
            // Consider 1am-5am as unusual for any user
            if (hour >= 1 && hour <= 5) {
                return {
                    detected: true,
                    score: 0.06,
                    reason: `Transaction at unusual hour (${this.formatHour(hour)})`,
                };
            }
            return { detected: false, score: 0, reason: '' };
        }

        // Check if current hour is outside preferred hours
        if (!preferredHours.includes(hour)) {
            // Calculate how far from preferred hours
            const minDistance = this.getMinHourDistance(hour, preferredHours);

            if (minDistance >= 6) {
                return {
                    detected: true,
                    score: 0.10,
                    reason: `Transaction at ${this.formatHour(hour)} - far from usual pattern`,
                };
            }

            if (minDistance >= 3) {
                return {
                    detected: true,
                    score: 0.05,
                    reason: `Transaction at ${this.formatHour(hour)} - outside usual hours`,
                };
            }
        }

        return { detected: false, score: 0, reason: '' };
    }

    /**
     * Check if day is unusual for user
     */
    private checkUnusualDay(
        day: number,
        preferredDays: number[],
        userHistory: UserTransactionHistory | null
    ): { detected: boolean; score: number; reason: string } {
        if (preferredDays.length === 0) {
            return { detected: false, score: 0, reason: '' };
        }

        if (!preferredDays.includes(day)) {
            const isWeekend = day === 0 || day === 6;

            // Higher score if user never transacts on this day type
            if (isWeekend && !preferredDays.includes(0) && !preferredDays.includes(6)) {
                return {
                    detected: true,
                    score: 0.06,
                    reason: `Weekend transaction from weekday-only user`,
                };
            }

            return {
                detected: true,
                score: 0.04,
                reason: `Transaction on ${this.getDayName(day)} - unusual day`,
            };
        }

        return { detected: false, score: 0, reason: '' };
    }

    /**
     * Check for late night transaction (globally suspicious)
     */
    private checkLateNight(hour: number): { detected: boolean; score: number; reason: string } {
        // 2am-5am is suspicious regardless of user patterns
        if (hour >= 2 && hour <= 5) {
            return {
                detected: true,
                score: 0.08,
                reason: `Late night/early morning transaction (${this.formatHour(hour)})`,
            };
        }

        // Midnight to 2am is slightly suspicious
        if (hour >= 0 && hour <= 1) {
            return {
                detected: true,
                score: 0.04,
                reason: `Late night transaction (${this.formatHour(hour)})`,
            };
        }

        return { detected: false, score: 0, reason: '' };
    }

    /**
     * Check weekend pattern for users who never transact weekends
     */
    private checkWeekendPattern(
        day: number,
        userHistory: UserTransactionHistory | null
    ): { detected: boolean; score: number; reason: string } {
        if (!userHistory || userHistory.transactions.length < 10) {
            return { detected: false, score: 0, reason: '' };
        }

        const isWeekend = day === 0 || day === 6;
        if (!isWeekend) {
            return { detected: false, score: 0, reason: '' };
        }

        // Check if user has any weekend transactions in history
        const weekendTx = userHistory.transactions.filter(tx => {
            const txDay = new Date(tx.timestamp).getDay();
            return txDay === 0 || txDay === 6;
        });

        // If user has 50+ transactions but 0 on weekends, this is unusual
        if (userHistory.statistics.totalTransactions >= 50 && weekendTx.length === 0) {
            return {
                detected: true,
                score: 0.08,
                reason: 'First weekend transaction from weekday-only user',
            };
        }

        return { detected: false, score: 0, reason: '' };
    }

    /**
     * Check if timestamp is on a holiday (simplified)
     */
    private checkHoliday(timestamp: Date): { detected: boolean; score: number; reason: string } {
        // Major US holidays (simplified - production would use holiday API)
        const month = timestamp.getMonth(); // 0-indexed
        const date = timestamp.getDate();

        const holidays: Array<{ month: number; date: number; name: string }> = [
            { month: 0, date: 1, name: "New Year's Day" },
            { month: 6, date: 4, name: 'Independence Day' },
            { month: 11, date: 25, name: 'Christmas' },
            { month: 11, date: 31, name: "New Year's Eve" },
        ];

        for (const holiday of holidays) {
            if (month === holiday.month && date === holiday.date) {
                return {
                    detected: true,
                    score: 0.04,
                    reason: `Transaction on ${holiday.name}`,
                };
            }
        }

        return { detected: false, score: 0, reason: '' };
    }

    /**
     * Check for activity burst at unusual time
     */
    private checkActivityBurst(
        hour: number,
        userHistory: UserTransactionHistory | null
    ): { detected: boolean; score: number; reason: string } {
        if (!userHistory) {
            return { detected: false, score: 0, reason: '' };
        }

        // Check if there are multiple transactions in the last hour at this unusual time
        const oneHourAgo = Date.now() - (60 * 60 * 1000);
        const recentTx = userHistory.transactions.filter(
            tx => new Date(tx.timestamp).getTime() > oneHourAgo
        );

        // If multiple transactions at unusual hour (1am-5am)
        if (hour >= 1 && hour <= 5 && recentTx.length >= 3) {
            return {
                detected: true,
                score: 0.10,
                reason: `Activity burst at unusual hour: ${recentTx.length} transactions in last hour at ${this.formatHour(hour)}`,
            };
        }

        return { detected: false, score: 0, reason: '' };
    }

    /**
     * Calculate minimum distance between hour and preferred hours
     */
    private getMinHourDistance(hour: number, preferredHours: number[]): number {
        let minDistance = 24;

        for (const prefHour of preferredHours) {
            const distance = Math.min(
                Math.abs(hour - prefHour),
                24 - Math.abs(hour - prefHour)
            );
            minDistance = Math.min(minDistance, distance);
        }

        return minDistance;
    }

    /**
     * Format hour for display
     */
    private formatHour(hour: number): string {
        const ampm = hour >= 12 ? 'PM' : 'AM';
        const hour12 = hour % 12 || 12;
        return `${hour12}:00 ${ampm}`;
    }

    /**
     * Get day name from day number
     */
    private getDayName(day: number): string {
        const days = ['Sunday', 'Monday', 'Tuesday', 'Wednesday', 'Thursday', 'Friday', 'Saturday'];
        return days[day];
    }

    /**
     * Build preferred hours from user history
     */
    buildPreferredHours(userHistory: UserTransactionHistory | null): number[] {
        if (!userHistory || userHistory.transactions.length < 10) {
            return [];
        }

        // Count transactions per hour
        const hourCounts: number[] = new Array(24).fill(0);

        for (const tx of userHistory.transactions) {
            const hour = new Date(tx.timestamp).getHours();
            hourCounts[hour]++;
        }

        // Find hours with significant activity (>10% of transactions)
        const threshold = userHistory.transactions.length * 0.1;
        const preferredHours: number[] = [];

        for (let hour = 0; hour < 24; hour++) {
            if (hourCounts[hour] >= threshold) {
                preferredHours.push(hour);
            }
        }

        return preferredHours;
    }

    /**
     * Build preferred days from user history
     */
    buildPreferredDays(userHistory: UserTransactionHistory | null): number[] {
        if (!userHistory || userHistory.transactions.length < 10) {
            return [];
        }

        // Count transactions per day of week
        const dayCounts: number[] = new Array(7).fill(0);

        for (const tx of userHistory.transactions) {
            const day = new Date(tx.timestamp).getDay();
            dayCounts[day]++;
        }

        // Find days with significant activity (>5% of transactions)
        const threshold = userHistory.transactions.length * 0.05;
        const preferredDays: number[] = [];

        for (let day = 0; day < 7; day++) {
            if (dayCounts[day] >= threshold) {
                preferredDays.push(day);
            }
        }

        return preferredDays;
    }
}

// Export singleton
export const timeAnalyzer = new TimeAnalyzer();
