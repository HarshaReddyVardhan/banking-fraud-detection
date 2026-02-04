import geoip from 'geoip-lite';
import { config } from '../config/config';
import { logger, fraudLogger } from '../middleware/requestLogger';
import { RiskFactor, GeoLocation, UserTransactionHistory } from '../types';

/**
 * Geographic Analyzer Service
 * Detects impossible travel and suspicious location patterns
 */
export class GeographicAnalyzer {
    private readonly impossibleTravelHours: number;
    private readonly weight: number;

    constructor() {
        this.impossibleTravelHours = config.analysis.geographic.impossibleTravelHours;
        this.weight = config.thresholds.geographicWeight;
    }

    /**
     * Analyze geographic risk for a transaction
     */
    async analyze(
        userId: string,
        transactionId: string,
        currentLocation: GeoLocation,
        userHistory: UserTransactionHistory | null,
        knownCountries: string[]
    ): Promise<RiskFactor> {
        const reasons: string[] = [];
        let totalScore = 0;

        try {
            // Check for impossible travel
            if (userHistory && userHistory.transactions.length > 0) {
                const impossibleTravel = this.checkImpossibleTravel(
                    currentLocation,
                    userHistory
                );

                if (impossibleTravel.detected) {
                    totalScore += impossibleTravel.score;
                    reasons.push(impossibleTravel.reason);

                    fraudLogger.geographicAnomaly(userId, transactionId, 'impossible_travel', {
                        currentCountry: currentLocation.country,
                        previousCountry: impossibleTravel.previousCountry,
                        timeDifferenceHours: impossibleTravel.timeDifferenceHours,
                        distanceKm: impossibleTravel.distanceKm,
                    });
                }
            }

            // Check for new country
            const isNewCountry = this.checkNewCountry(currentLocation, knownCountries);
            if (isNewCountry.detected) {
                totalScore += isNewCountry.score;
                reasons.push(isNewCountry.reason);

                fraudLogger.geographicAnomaly(userId, transactionId, 'new_country', {
                    country: currentLocation.country,
                    knownCountries: knownCountries.length,
                });
            }

            // Check for high-risk country
            const highRiskCountry = this.checkHighRiskCountry(currentLocation);
            if (highRiskCountry.detected) {
                totalScore += highRiskCountry.score;
                reasons.push(highRiskCountry.reason);

                fraudLogger.geographicAnomaly(userId, transactionId, 'high_risk_country', {
                    country: currentLocation.country,
                    riskLevel: highRiskCountry.riskLevel,
                });
            }

            // Check for VPN/proxy indicators
            if (currentLocation.ip) {
                const vpnCheck = await this.checkVPNIndicators();
                if (vpnCheck.detected) {
                    totalScore += vpnCheck.score;
                    reasons.push(vpnCheck.reason);
                }
            }

            // Cap the total geographic score
            totalScore = Math.min(totalScore, 0.50);

            const riskFactor: RiskFactor = {
                method: 'GEOGRAPHIC',
                score: totalScore,
                weight: this.weight,
                contributedScore: totalScore * this.weight,
                reason: reasons.length > 0
                    ? reasons.join('; ')
                    : 'Normal geographic pattern',
                details: {
                    country: currentLocation.country,
                    city: currentLocation.city,
                    isNewCountry: isNewCountry.detected,
                    knownCountries: knownCountries.length,
                },
            };

            logger.debug('Geographic analysis complete', {
                userId,
                transactionId,
                score: totalScore,
                country: currentLocation.country,
            });

            return riskFactor;
        } catch (error) {
            logger.error('Geographic analysis error', { userId, transactionId, error });

            return {
                method: 'GEOGRAPHIC',
                score: 0,
                weight: this.weight,
                contributedScore: 0,
                reason: 'Geographic analysis unavailable',
                details: { error: 'Analysis failed' },
            };
        }
    }

    /**
     * Get location from IP address
     */
    getLocationFromIp(ip: string): GeoLocation {
        try {
            const geo = geoip.lookup(ip);

            if (geo) {
                return {
                    ip,
                    country: geo.country,
                    city: geo.city,
                    latitude: geo.ll?.[0] ?? null,
                    longitude: geo.ll?.[1] ?? null,
                    timezone: geo.timezone,
                };
            }

            return {
                ip,
                country: null,
                city: null,
                latitude: null,
                longitude: null,
            };
        } catch (error) {
            logger.error('Failed to get location from IP', { ip, error });
            return {
                ip,
                country: null,
                city: null,
                latitude: null,
                longitude: null,
            };
        }
    }

    /**
     * Check for impossible travel (login from distant location too quickly)
     */
    private checkImpossibleTravel(
        currentLocation: GeoLocation,
        userHistory: UserTransactionHistory
    ): {
        detected: boolean;
        score: number;
        reason: string;
        previousCountry?: string;
        timeDifferenceHours?: number;
        distanceKm?: number;
    } {
        const result = {
            detected: false,
            score: 0,
            reason: '',
        };

        if (!currentLocation.latitude || !currentLocation.longitude) {
            return result;
        }

        // Get the most recent transaction with location data
        const recentTx = userHistory.transactions.find(
            tx => tx.country !== undefined
        );

        if (!recentTx || !recentTx.timestamp) {
            return result;
        }

        // Get location of previous transaction (simplified - would need lat/long storage)
        // For now, check if country changed in impossibly short time
        if (recentTx.country && currentLocation.country && recentTx.country !== currentLocation.country) {
            const timeDiff = new Date().getTime() - new Date(recentTx.timestamp).getTime();
            const hoursDiff = timeDiff / (1000 * 60 * 60);

            // If different country in less than 2 hours, likely impossible
            if (hoursDiff < this.impossibleTravelHours) {
                return {
                    detected: true,
                    score: 0.35,
                    reason: `Impossible travel: Transaction from ${currentLocation.country} ${hoursDiff.toFixed(1)} hours after ${recentTx.country}`,
                    previousCountry: recentTx.country,
                    timeDifferenceHours: hoursDiff,
                };
            }
        }

        return result;
    }

    /**
     * Calculate distance between two coordinates (Haversine formula)
     */
    calculateDistance(
        lat1: number,
        lon1: number,
        lat2: number,
        lon2: number
    ): number {
        const R = 6371; // Earth's radius in km
        const dLat = this.toRad(lat2 - lat1);
        const dLon = this.toRad(lon2 - lon1);

        const a =
            Math.sin(dLat / 2) * Math.sin(dLat / 2) +
            Math.cos(this.toRad(lat1)) *
            Math.cos(this.toRad(lat2)) *
            Math.sin(dLon / 2) *
            Math.sin(dLon / 2);

        const c = 2 * Math.atan2(Math.sqrt(a), Math.sqrt(1 - a));
        return R * c;
    }

    private toRad(deg: number): number {
        return deg * (Math.PI / 180);
    }

    /**
     * Check if this is a new country for the user
     */
    private checkNewCountry(
        currentLocation: GeoLocation,
        knownCountries: string[]
    ): { detected: boolean; score: number; reason: string } {
        if (!currentLocation.country) {
            return { detected: false, score: 0, reason: '' };
        }

        const isNew = !knownCountries.includes(currentLocation.country);

        if (isNew && knownCountries.length > 0) {
            return {
                detected: true,
                score: 0.15,
                reason: `First transaction from ${currentLocation.country}`,
            };
        }

        return { detected: false, score: 0, reason: '' };
    }

    /**
     * Check if country is high-risk for fraud
     */
    private checkHighRiskCountry(
        currentLocation: GeoLocation
    ): { detected: boolean; score: number; reason: string; riskLevel: string } {
        if (!currentLocation.country) {
            return { detected: false, score: 0, reason: '', riskLevel: 'unknown' };
        }

        // High-risk countries list (simplified - would use external threat intelligence)
        const highRiskCountries: Record<string, { score: number; level: string }> = {
            'NG': { score: 0.12, level: 'elevated' },
            'RU': { score: 0.10, level: 'elevated' },
            'CN': { score: 0.08, level: 'moderate' },
            'VN': { score: 0.08, level: 'moderate' },
            'IN': { score: 0.05, level: 'low' },
            'PH': { score: 0.06, level: 'low' },
            'UA': { score: 0.08, level: 'moderate' },
            'RO': { score: 0.07, level: 'moderate' },
        };

        const riskData = highRiskCountries[currentLocation.country];

        if (riskData) {
            return {
                detected: true,
                score: riskData.score,
                reason: `Transaction from ${riskData.level}-risk region (${currentLocation.country})`,
                riskLevel: riskData.level,
            };
        }

        return { detected: false, score: 0, reason: '', riskLevel: 'low' };
    }

    /**
     * Check for VPN/proxy indicators
     */
    private async checkVPNIndicators(
    ): Promise<{ detected: boolean; score: number; reason: string }> {
        // Simplified VPN detection - would use external VPN detection service
        // Check for common datacenter IP ranges, TOR exit nodes, etc.

        // Placeholder - return false for now
        // In production, integrate with services like MaxMind, IP2Proxy, etc.
        return { detected: false, score: 0, reason: '' };
    }

    /**
     * Check if user is a frequent traveler (for whitelisting)
     */
    isFrequentTraveler(
        knownCountries: string[],
        transactionCount: number
    ): boolean {
        // If user has transactions from 5+ countries with 50+ transactions,
        // they're likely a frequent traveler
        return knownCountries.length >= 5 && transactionCount >= 50;
    }
}

// Export singleton
export const geographicAnalyzer = new GeographicAnalyzer();
