import { config } from '../config/config';
import { logger, fraudLogger } from '../middleware/requestLogger';
import { cacheService } from './CacheService';
import { RiskFactor, DeviceInfo, UserTransactionHistory } from '../types';
import { FraudBlocklist } from '../models/FraudBlocklist';
import crypto from 'crypto';
import UAParser from 'ua-parser-js';

/**
 * Device Analyzer Service
 * Detects transactions from unknown, suspicious, or blocked devices
 */
export class DeviceAnalyzer {
    private readonly weight: number;
    private readonly uaParser: UAParser;

    constructor() {
        this.weight = config.thresholds.deviceWeight;
        this.uaParser = new UAParser();
    }

    /**
     * Analyze device risk for a transaction
     */
    async analyze(
        userId: string,
        transactionId: string,
        deviceFingerprint: string | undefined,
        userAgent: string | undefined,
        knownDevices: string[],
        userHistory: UserTransactionHistory | null
    ): Promise<RiskFactor> {
        const reasons: string[] = [];
        let totalScore = 0;

        try {
            // If no device info provided, add moderate risk
            if (!deviceFingerprint && !userAgent) {
                return {
                    method: 'DEVICE',
                    score: 0.12,
                    weight: this.weight,
                    contributedScore: 0.12 * this.weight,
                    reason: 'No device information available',
                    details: {
                        hasFingerprint: false,
                        hasUserAgent: false,
                    },
                };
            }

            // Check blocklist first
            if (deviceFingerprint) {
                const blocklistMatch = await this.checkBlocklist(deviceFingerprint);
                if (blocklistMatch.detected) {
                    fraudLogger.blocklistMatch('DEVICE', deviceFingerprint, transactionId);
                    return {
                        method: 'DEVICE',
                        score: 1.0,
                        weight: this.weight,
                        contributedScore: 1.0,
                        reason: blocklistMatch.reason,
                        details: {
                            deviceFingerprint: this.maskFingerprint(deviceFingerprint),
                            blocked: true,
                        },
                    };
                }
            }

            // Check if this is a new device
            const isNewDevice = this.checkNewDevice(deviceFingerprint, knownDevices);
            if (isNewDevice.detected) {
                totalScore += isNewDevice.score;
                reasons.push(isNewDevice.reason);
            }

            // Get or compute device info
            let deviceInfo: DeviceInfo | null = null;
            if (deviceFingerprint) {
                deviceInfo = await cacheService.getDeviceInfo(deviceFingerprint);
                if (!deviceInfo) {
                    deviceInfo = this.createDeviceInfo(deviceFingerprint, userId);
                    await cacheService.setDeviceInfo(deviceFingerprint, deviceInfo);
                }
            }

            // Check device trust score
            if (deviceInfo && deviceInfo.trustScore < 0.5) {
                totalScore += (1 - deviceInfo.trustScore) * 0.15;
                reasons.push(`Low device trust score (${deviceInfo.trustScore.toFixed(2)})`);
            }

            // Analyze user agent
            if (userAgent) {
                const uaAnalysis = this.analyzeUserAgent(userAgent);
                if (uaAnalysis.detected) {
                    totalScore += uaAnalysis.score;
                    reasons.push(uaAnalysis.reason);
                }
            }

            // Check for VPN/proxy indicators in user agent
            if (userAgent) {
                const proxyCheck = this.checkProxyIndicators(userAgent);
                if (proxyCheck.detected) {
                    totalScore += proxyCheck.score;
                    reasons.push(proxyCheck.reason);
                }
            }

            // Check device count - if user has many unique devices, less suspicious
            // But if suddenly a new device after stable pattern, more suspicious
            const devicePattern = this.checkDevicePattern(
                deviceFingerprint,
                knownDevices,
                userHistory
            );
            if (devicePattern.detected) {
                totalScore += devicePattern.score;
                reasons.push(devicePattern.reason);
            }

            // Check for device fingerprint anomalies
            if (deviceFingerprint) {
                const fingerprintCheck = this.checkFingerprintQuality(deviceFingerprint);
                if (fingerprintCheck.detected) {
                    totalScore += fingerprintCheck.score;
                    reasons.push(fingerprintCheck.reason);
                }
            }

            // Cap the total device score
            totalScore = Math.min(totalScore, 0.40);

            const riskFactor: RiskFactor = {
                method: 'DEVICE',
                score: totalScore,
                weight: this.weight,
                contributedScore: totalScore * this.weight,
                reason: reasons.length > 0
                    ? reasons.join('; ')
                    : 'Known device',
                details: {
                    deviceFingerprint: deviceFingerprint ? this.maskFingerprint(deviceFingerprint) : null,
                    isNewDevice: isNewDevice.detected,
                    knownDeviceCount: knownDevices.length,
                    trustScore: deviceInfo?.trustScore,
                    parsedUserAgent: userAgent ? this.parseUserAgentSummary(userAgent) : null,
                },
            };

            logger.debug('Device analysis complete', {
                userId,
                transactionId,
                score: totalScore,
                isNewDevice: isNewDevice.detected,
            });

            return riskFactor;
        } catch (error) {
            logger.error('Device analysis error', { userId, transactionId, error });

            return {
                method: 'DEVICE',
                score: 0,
                weight: this.weight,
                contributedScore: 0,
                reason: 'Device analysis unavailable',
                details: { error: 'Analysis failed' },
            };
        }
    }

    /**
     * Check if device is in blocklist
     */
    private async checkBlocklist(
        deviceFingerprint: string
    ): Promise<{ detected: boolean; reason: string }> {
        try {
            // Check cache first
            const cached = await cacheService.isInBlocklist('DEVICE', deviceFingerprint);
            if (cached && cached.isActive) {
                return {
                    detected: true,
                    reason: 'Device is on fraud blocklist',
                };
            }

            // Check database
            const hash = this.hashValue(deviceFingerprint);
            const entry = await FraudBlocklist.findOne({
                where: {
                    type: 'DEVICE',
                    valueHash: hash,
                    isActive: true,
                },
            });

            if (entry) {
                await entry.recordMatch();
                await cacheService.addToBlocklistCache({
                    id: entry.id,
                    type: 'DEVICE',
                    value: entry.value,
                    reason: entry.reason,
                    addedBy: entry.addedBy,
                    addedAt: entry.createdAt.toISOString(),
                    isActive: true,
                });

                return {
                    detected: true,
                    reason: `Device blocked: ${entry.reason}`,
                };
            }

            return { detected: false, reason: '' };
        } catch (error) {
            logger.error('Device blocklist check error', { error });
            return { detected: false, reason: '' };
        }
    }

    /**
     * Check if device is new for user
     */
    private checkNewDevice(
        deviceFingerprint: string | undefined,
        knownDevices: string[]
    ): { detected: boolean; score: number; reason: string } {
        if (!deviceFingerprint) {
            return { detected: false, score: 0, reason: '' };
        }

        const isKnown = knownDevices.includes(deviceFingerprint);

        if (!isKnown && knownDevices.length > 0) {
            return {
                detected: true,
                score: 0.12,
                reason: 'New device for this user',
            };
        }

        // If user has no known devices, first device is slightly suspicious
        if (!isKnown && knownDevices.length === 0) {
            return {
                detected: true,
                score: 0.06,
                reason: 'First recorded device',
            };
        }

        return { detected: false, score: 0, reason: '' };
    }

    /**
     * Create new device info
     */
    private createDeviceInfo(fingerprint: string, userId: string): DeviceInfo {
        return {
            fingerprint,
            userId,
            isKnown: false,
            firstSeen: new Date().toISOString(),
            lastSeen: new Date().toISOString(),
            transactionCount: 0,
            trustScore: 0.5, // Neutral trust for new device
            isFlagged: false,
        };
    }

    /**
     * Analyze user agent for suspicious patterns
     */
    private analyzeUserAgent(
        userAgent: string
    ): { detected: boolean; score: number; reason: string } {
        this.uaParser.setUA(userAgent);
        const result = this.uaParser.getResult();

        // Check for headless browsers (bot indicators)
        const headlessPatterns = [
            'HeadlessChrome',
            'PhantomJS',
            'Selenium',
            'puppeteer',
            'playwright',
            'crawl',
            'bot',
            'spider',
        ];

        const lowerUA = userAgent.toLowerCase();
        for (const pattern of headlessPatterns) {
            if (lowerUA.includes(pattern.toLowerCase())) {
                return {
                    detected: true,
                    score: 0.25,
                    reason: `Suspicious user agent: possible automated browser (${pattern})`,
                };
            }
        }

        // Check for very old browsers
        if (result.browser.version) {
            const majorVersion = parseInt(result.browser.version.split('.')[0], 10);

            if (result.browser.name === 'Chrome' && majorVersion < 70) {
                return {
                    detected: true,
                    score: 0.08,
                    reason: 'Very outdated Chrome browser',
                };
            }

            if (result.browser.name === 'Firefox' && majorVersion < 60) {
                return {
                    detected: true,
                    score: 0.08,
                    reason: 'Very outdated Firefox browser',
                };
            }
        }

        // Check for suspicious OS/browser combinations
        if (result.os.name === 'Linux' &&
            result.browser.name !== 'Firefox' &&
            result.browser.name !== 'Chrome') {
            return {
                detected: true,
                score: 0.05,
                reason: 'Unusual OS/browser combination',
            };
        }

        // Check for empty/minimal user agents
        if (userAgent.length < 20) {
            return {
                detected: true,
                score: 0.15,
                reason: 'Minimal or empty user agent string',
            };
        }

        return { detected: false, score: 0, reason: '' };
    }

    /**
     * Check for VPN/proxy indicators
     */
    private checkProxyIndicators(
        userAgent: string
    ): { detected: boolean; score: number; reason: string } {
        // Some user agents indicate proxy/VPN usage
        const proxyPatterns = ['proxy', 'vpn', 'tor', 'anonymous'];

        const lowerUA = userAgent.toLowerCase();
        for (const pattern of proxyPatterns) {
            if (lowerUA.includes(pattern)) {
                return {
                    detected: true,
                    score: 0.10,
                    reason: `Possible VPN/proxy detected in user agent`,
                };
            }
        }

        return { detected: false, score: 0, reason: '' };
    }

    /**
     * Check device pattern changes
     */
    private checkDevicePattern(
        deviceFingerprint: string | undefined,
        knownDevices: string[],
        userHistory: UserTransactionHistory | null
    ): { detected: boolean; score: number; reason: string } {
        if (!userHistory || !deviceFingerprint) {
            return { detected: false, score: 0, reason: '' };
        }

        // If user always uses 1-2 devices and suddenly a new one appears
        // after many transactions, it's more suspicious
        if (knownDevices.length <= 2 &&
            userHistory.statistics.totalTransactions >= 50 &&
            !knownDevices.includes(deviceFingerprint)) {
            return {
                detected: true,
                score: 0.10,
                reason: 'Stable device pattern disrupted - new device after consistent usage',
            };
        }

        return { detected: false, score: 0, reason: '' };
    }

    /**
     * Check fingerprint quality (detect spoofed/synthetic fingerprints)
     */
    private checkFingerprintQuality(
        fingerprint: string
    ): { detected: boolean; score: number; reason: string } {
        // Check for obviously fake fingerprints
        if (fingerprint.length < 16) {
            return {
                detected: true,
                score: 0.15,
                reason: 'Suspicious device fingerprint format',
            };
        }

        // Check for repeated patterns
        const uniqueChars = new Set(fingerprint).size;
        if (uniqueChars < 4) {
            return {
                detected: true,
                score: 0.20,
                reason: 'Potentially spoofed device fingerprint',
            };
        }

        // Check for sequential patterns
        if (/^(.)\1+$/.test(fingerprint) || fingerprint === '0'.repeat(fingerprint.length)) {
            return {
                detected: true,
                score: 0.25,
                reason: 'Invalid device fingerprint detected',
            };
        }

        return { detected: false, score: 0, reason: '' };
    }

    /**
     * Hash value for storage
     */
    private hashValue(value: string): string {
        return crypto.createHash('sha256').update(value).digest('hex');
    }

    /**
     * Mask fingerprint for logging
     */
    private maskFingerprint(fingerprint: string): string {
        if (fingerprint.length <= 8) {
            return '****';
        }
        return fingerprint.substring(0, 4) + '****' + fingerprint.substring(fingerprint.length - 4);
    }

    /**
     * Parse user agent summary
     */
    private parseUserAgentSummary(userAgent: string): Record<string, string | undefined> {
        this.uaParser.setUA(userAgent);
        const result = this.uaParser.getResult();

        return {
            browser: `${result.browser.name} ${result.browser.version}`,
            os: `${result.os.name} ${result.os.version}`,
            device: result.device.type || 'desktop',
        };
    }

    /**
     * Update device trust score
     */
    async updateDeviceTrust(
        fingerprint: string,
        trustDelta: number
    ): Promise<void> {
        const deviceInfo = await cacheService.getDeviceInfo(fingerprint);
        if (deviceInfo) {
            deviceInfo.trustScore = Math.max(0, Math.min(1, deviceInfo.trustScore + trustDelta));
            deviceInfo.lastSeen = new Date().toISOString();
            deviceInfo.transactionCount++;
            await cacheService.setDeviceInfo(fingerprint, deviceInfo);
        }
    }
}

// Export singleton
export const deviceAnalyzer = new DeviceAnalyzer();
