import Redis, { RedisOptions } from 'ioredis';
import { config } from '../config/config';
import { logger } from '../middleware/requestLogger';
import { UserTransactionHistory, DeviceInfo, RecipientInfo, BlocklistEntry } from '../types';
import crypto from 'crypto';

/**
 * Redis Cache Service for fraud detection
 * Provides caching for user histories, blocklists, and computed risk data
 */
export class CacheService {
    private redis: Redis | null = null;
    private isConnected: boolean = false;
    private readonly keyPrefix: string;

    constructor() {
        this.keyPrefix = config.redis.keyPrefix;
    }

    /**
     * Connect to Redis
     */
    async connect(): Promise<void> {
        if (this.isConnected) return;

        try {
            const options: RedisOptions = {
                host: config.redis.host,
                port: config.redis.port,
                db: config.redis.db,
                lazyConnect: true,
                maxRetriesPerRequest: 3,
                retryStrategy: (times: number) => {
                    if (times > 10) {
                        logger.error('Redis max retries reached');
                        return null;
                    }
                    return Math.min(times * 100, 3000);
                },
            };

            if (config.redis.password) {
                options.password = config.redis.password;
            }

            if (config.redis.tls) {
                options.tls = {};
            }

            this.redis = new Redis(options);

            this.redis.on('connect', () => {
                logger.info('Redis connected');
                this.isConnected = true;
            });

            this.redis.on('error', (error) => {
                logger.error('Redis error', { error });
            });

            this.redis.on('close', () => {
                logger.warn('Redis connection closed');
                this.isConnected = false;
            });

            await this.redis.connect();
            this.isConnected = true;
        } catch (error) {
            logger.error('Failed to connect to Redis', { error });
            // Don't throw - allow service to run without Redis
        }
    }

    /**
     * Disconnect from Redis
     */
    async disconnect(): Promise<void> {
        if (this.redis) {
            await this.redis.quit();
            this.isConnected = false;
            logger.info('Redis disconnected');
        }
    }

    /**
     * Check if Redis is connected
     */
    isRedisConnected(): boolean {
        return this.isConnected;
    }

    // ==================== User Transaction History ====================

    /**
     * Get user transaction history from cache
     */
    async getUserHistory(userId: string): Promise<UserTransactionHistory | null> {
        if (!this.redis || !this.isConnected) return null;

        try {
            const key = `${this.keyPrefix}user:history:${userId}`;
            const data = await this.redis.get(key);

            if (data) {
                return JSON.parse(data) as UserTransactionHistory;
            }
            return null;
        } catch (error) {
            logger.error('Failed to get user history from cache', { userId, error });
            return null;
        }
    }

    /**
     * Set user transaction history in cache
     */
    async setUserHistory(userId: string, history: UserTransactionHistory): Promise<void> {
        if (!this.redis || !this.isConnected) return;

        try {
            const key = `${this.keyPrefix}user:history:${userId}`;
            await this.redis.set(
                key,
                JSON.stringify(history),
                'EX',
                config.cache.userHistoryTTL
            );
        } catch (error) {
            logger.error('Failed to set user history in cache', { userId, error });
        }
    }

    // ==================== User Risk Score ====================

    /**
     * Get user risk score from cache
     */
    async getUserRiskScore(userId: string): Promise<number | null> {
        if (!this.redis || !this.isConnected) return null;

        try {
            const key = `${this.keyPrefix}user:risk:${userId}`;
            const score = await this.redis.get(key);
            return score ? parseFloat(score) : null;
        } catch (error) {
            logger.error('Failed to get user risk score from cache', { userId, error });
            return null;
        }
    }

    /**
     * Set user risk score in cache
     */
    async setUserRiskScore(userId: string, score: number): Promise<void> {
        if (!this.redis || !this.isConnected) return;

        try {
            const key = `${this.keyPrefix}user:risk:${userId}`;
            await this.redis.set(
                key,
                score.toString(),
                'EX',
                config.cache.userRiskScoreTTL
            );
        } catch (error) {
            logger.error('Failed to set user risk score in cache', { userId, error });
        }
    }

    // ==================== Device Information ====================

    /**
     * Get device info from cache
     */
    async getDeviceInfo(fingerprint: string): Promise<DeviceInfo | null> {
        if (!this.redis || !this.isConnected) return null;

        try {
            const key = `${this.keyPrefix}device:${this.hashValue(fingerprint)}`;
            const data = await this.redis.get(key);
            return data ? JSON.parse(data) as DeviceInfo : null;
        } catch (error) {
            logger.error('Failed to get device info from cache', { error });
            return null;
        }
    }

    /**
     * Set device info in cache
     */
    async setDeviceInfo(fingerprint: string, info: DeviceInfo): Promise<void> {
        if (!this.redis || !this.isConnected) return;

        try {
            const key = `${this.keyPrefix}device:${this.hashValue(fingerprint)}`;
            await this.redis.set(
                key,
                JSON.stringify(info),
                'EX',
                config.cache.deviceTTL
            );
        } catch (error) {
            logger.error('Failed to set device info in cache', { error });
        }
    }

    // ==================== Recipient Information ====================

    /**
     * Get recipient info from cache
     */
    async getRecipientInfo(recipientId: string): Promise<RecipientInfo | null> {
        if (!this.redis || !this.isConnected) return null;

        try {
            const key = `${this.keyPrefix}recipient:${recipientId}`;
            const data = await this.redis.get(key);
            return data ? JSON.parse(data) as RecipientInfo : null;
        } catch (error) {
            logger.error('Failed to get recipient info from cache', { error });
            return null;
        }
    }

    /**
     * Set recipient info in cache
     */
    async setRecipientInfo(recipientId: string, info: RecipientInfo): Promise<void> {
        if (!this.redis || !this.isConnected) return;

        try {
            const key = `${this.keyPrefix}recipient:${recipientId}`;
            await this.redis.set(
                key,
                JSON.stringify(info),
                'EX',
                config.cache.userHistoryTTL
            );
        } catch (error) {
            logger.error('Failed to set recipient info in cache', { error });
        }
    }

    // ==================== Blocklist Cache ====================

    /**
     * Check if value is in blocklist cache
     */
    async isInBlocklist(type: string, value: string): Promise<BlocklistEntry | null> {
        if (!this.redis || !this.isConnected) return null;

        try {
            const hash = this.hashValue(value);
            const key = `${this.keyPrefix}blocklist:${type}:${hash}`;
            const data = await this.redis.get(key);
            return data ? JSON.parse(data) as BlocklistEntry : null;
        } catch (error) {
            logger.error('Failed to check blocklist cache', { type, error });
            return null;
        }
    }

    /**
     * Add entry to blocklist cache
     */
    async addToBlocklistCache(entry: BlocklistEntry): Promise<void> {
        if (!this.redis || !this.isConnected) return;

        try {
            const hash = this.hashValue(entry.value);
            const key = `${this.keyPrefix}blocklist:${entry.type}:${hash}`;
            await this.redis.set(
                key,
                JSON.stringify(entry),
                'EX',
                config.cache.blocklistTTL
            );
        } catch (error) {
            logger.error('Failed to add to blocklist cache', { error });
        }
    }

    /**
     * Remove entry from blocklist cache
     */
    async removeFromBlocklistCache(type: string, value: string): Promise<void> {
        if (!this.redis || !this.isConnected) return;

        try {
            const hash = this.hashValue(value);
            const key = `${this.keyPrefix}blocklist:${type}:${hash}`;
            await this.redis.del(key);
        } catch (error) {
            logger.error('Failed to remove from blocklist cache', { type, error });
        }
    }

    // ==================== Velocity Tracking ====================

    /**
     * Increment velocity counter
     */
    async incrementVelocity(
        userId: string,
        window: '5m' | '1h' | '24h',
        amount: number
    ): Promise<{ count: number; totalAmount: number }> {
        if (!this.redis || !this.isConnected) {
            return { count: 0, totalAmount: 0 };
        }

        const ttl = window === '5m' ? 300 : window === '1h' ? 3600 : 86400;
        const countKey = `${this.keyPrefix}velocity:count:${userId}:${window}`;
        const amountKey = `${this.keyPrefix}velocity:amount:${userId}:${window}`;

        try {
            const pipeline = this.redis.pipeline();

            pipeline.incr(countKey);
            pipeline.expire(countKey, ttl);
            pipeline.incrbyfloat(amountKey, amount);
            pipeline.expire(amountKey, ttl);

            const results = await pipeline.exec();

            const count = (results?.[0]?.[1] as number) || 0;
            const totalAmount = parseFloat((results?.[2]?.[1] as string) || '0');

            return { count, totalAmount };
        } catch (error) {
            logger.error('Failed to increment velocity', { userId, window, error });
            return { count: 0, totalAmount: 0 };
        }
    }

    /**
     * Get velocity data for user
     */
    async getVelocity(userId: string, window: '5m' | '1h' | '24h'): Promise<{ count: number; totalAmount: number }> {
        if (!this.redis || !this.isConnected) {
            return { count: 0, totalAmount: 0 };
        }

        const countKey = `${this.keyPrefix}velocity:count:${userId}:${window}`;
        const amountKey = `${this.keyPrefix}velocity:amount:${userId}:${window}`;

        try {
            const pipeline = this.redis.pipeline();
            pipeline.get(countKey);
            pipeline.get(amountKey);

            const results = await pipeline.exec();

            const count = parseInt((results?.[0]?.[1] as string) || '0', 10);
            const totalAmount = parseFloat((results?.[1]?.[1] as string) || '0');

            return { count, totalAmount };
        } catch (error) {
            logger.error('Failed to get velocity', { userId, window, error });
            return { count: 0, totalAmount: 0 };
        }
    }

    // ==================== Analysis Result Cache ====================

    /**
     * Get cached analysis result
     */
    async getCachedAnalysis(transactionId: string): Promise<Record<string, unknown> | null> {
        if (!this.redis || !this.isConnected) return null;

        try {
            const key = `${this.keyPrefix}analysis:${transactionId}`;
            const data = await this.redis.get(key);
            return data ? JSON.parse(data) : null;
        } catch (error) {
            logger.error('Failed to get cached analysis', { transactionId, error });
            return null;
        }
    }

    /**
     * Cache analysis result (for idempotency)
     */
    async cacheAnalysis(transactionId: string, result: Record<string, unknown>): Promise<void> {
        if (!this.redis || !this.isConnected) return;

        try {
            const key = `${this.keyPrefix}analysis:${transactionId}`;
            await this.redis.set(
                key,
                JSON.stringify(result),
                'EX',
                config.cache.analysisResultTTL
            );
        } catch (error) {
            logger.error('Failed to cache analysis', { transactionId, error });
        }
    }

    // ==================== Utility Methods ====================

    /**
     * Hash value for cache keys (privacy)
     */
    private hashValue(value: string): string {
        return crypto.createHash('sha256').update(value).digest('hex').substring(0, 16);
    }

    /**
     * Clear all cache for a user
     */
    async clearUserCache(userId: string): Promise<void> {
        if (!this.redis || !this.isConnected) return;

        try {
            const pattern = `${this.keyPrefix}*:${userId}*`;
            const keys = await this.redis.keys(pattern);

            if (keys.length > 0) {
                await this.redis.del(...keys);
                logger.info('Cleared user cache', { userId, keysCleared: keys.length });
            }
        } catch (error) {
            logger.error('Failed to clear user cache', { userId, error });
        }
    }

    /**
     * Health check
     */
    async healthCheck(): Promise<boolean> {
        if (!this.redis || !this.isConnected) return false;

        try {
            const result = await this.redis.ping();
            return result === 'PONG';
        } catch {
            return false;
        }
    }
}

// Export singleton
export const cacheService = new CacheService();
