import fs from 'fs';
import path from 'path';

// Validation helper
function requireEnv(name: string): string {
    const value = process.env[name];
    if (!value) {
        throw new Error(`Missing required environment variable: ${name}`);
    }
    return value;
}

function optionalEnv(name: string, defaultValue: string): string {
    return process.env[name] ?? defaultValue;
}

function optionalEnvInt(name: string, defaultValue: number): number {
    const value = process.env[name];
    return value ? parseInt(value, 10) : defaultValue;
}

function optionalEnvFloat(name: string, defaultValue: number): number {
    const value = process.env[name];
    return value ? parseFloat(value) : defaultValue;
}

function optionalEnvBool(name: string, defaultValue: boolean): boolean {
    const value = process.env[name];
    if (!value) return defaultValue;
    return value.toLowerCase() === 'true';
}

export const config = {
    // Server
    nodeEnv: optionalEnv('NODE_ENV', 'development'),
    port: optionalEnvInt('PORT', 3003),
    host: optionalEnv('HOST', '0.0.0.0'),
    serviceName: 'banking-fraud-detection',

    // Database
    database: {
        host: requireEnv('DB_HOST'),
        port: optionalEnvInt('DB_PORT', 5432),
        name: requireEnv('DB_NAME'),
        user: requireEnv('DB_USER'),
        password: requireEnv('DB_PASSWORD'),
        ssl: optionalEnvBool('DB_SSL', true),
        sslRejectUnauthorized: optionalEnvBool('DB_SSL_REJECT_UNAUTHORIZED', true),
        pool: {
            min: optionalEnvInt('DB_POOL_MIN', 5),
            max: optionalEnvInt('DB_POOL_MAX', 50),
            acquire: optionalEnvInt('DB_POOL_ACQUIRE', 30000),
            idle: optionalEnvInt('DB_POOL_IDLE', 10000),
        },
    },

    // Redis for caching
    redis: {
        host: requireEnv('REDIS_HOST'),
        port: optionalEnvInt('REDIS_PORT', 6379),
        password: process.env['REDIS_PASSWORD'],
        tls: optionalEnvBool('REDIS_TLS', false),
        db: optionalEnvInt('REDIS_DB', 0),
        keyPrefix: 'fraud:',
    },

    // Kafka configuration
    kafka: {
        brokers: optionalEnv('KAFKA_BROKERS', 'localhost:9092').split(','),
        clientId: optionalEnv('KAFKA_CLIENT_ID', 'fraud-detection-service'),
        groupId: optionalEnv('KAFKA_GROUP_ID', 'fraud-detection-group'),
        topics: {
            transactionCreated: optionalEnv('KAFKA_TOPIC_IN', 'banking.transfers.created'),
            fraudAnalysis: optionalEnv('KAFKA_TOPIC_ANALYSIS', 'banking.fraud.analysis'),
            fraudSuspected: optionalEnv('KAFKA_TOPIC_SUSPECTED', 'banking.fraud.suspected'),
            fraudManualReview: optionalEnv('KAFKA_TOPIC_REVIEW', 'banking.fraud.manual_review'),
            fraudReviewComplete: optionalEnv('KAFKA_TOPIC_REVIEW_COMPLETE', 'banking.fraud.review_complete'),
        },
        connectionTimeout: optionalEnvInt('KAFKA_CONNECTION_TIMEOUT', 30000),
        sessionTimeout: optionalEnvInt('KAFKA_SESSION_TIMEOUT', 30000),
    },

    // ML Model configuration
    ml: {
        modelPath: optionalEnv('ML_MODEL_PATH', './models/fraud-model.onnx'),
        modelVersion: optionalEnv('ML_MODEL_VERSION', 'v2.5'),
        fallbackModelPath: optionalEnv('ML_FALLBACK_MODEL_PATH', './models/fraud-model-v2.4.onnx'),
        inferenceTimeoutMs: optionalEnvInt('ML_INFERENCE_TIMEOUT', 5000),
        useGPU: optionalEnvBool('ML_USE_GPU', false),
        modelHashValidation: optionalEnvBool('ML_HASH_VALIDATION', true),
        expectedModelHash: process.env['ML_MODEL_SIGNATURE'],
    },

    // Fraud detection thresholds
    thresholds: {
        // Decision thresholds
        approveMax: optionalEnvFloat('THRESHOLD_APPROVE_MAX', 0.50),
        suspiciousMin: optionalEnvFloat('THRESHOLD_SUSPICIOUS_MIN', 0.50),
        suspiciousMax: optionalEnvFloat('THRESHOLD_SUSPICIOUS_MAX', 0.80),
        rejectMin: optionalEnvFloat('THRESHOLD_REJECT_MIN', 0.80),

        // Risk score contributions
        velocityWeights: {
            fiveMinute: optionalEnvFloat('VELOCITY_WEIGHT_5MIN', 0.15),
            oneHour: optionalEnvFloat('VELOCITY_WEIGHT_1HOUR', 0.10),
            twentyFourHours: optionalEnvFloat('VELOCITY_WEIGHT_24HOURS', 0.08),
        },
        geographicWeight: optionalEnvFloat('GEOGRAPHIC_WEIGHT', 0.35),
        amountWeight: optionalEnvFloat('AMOUNT_WEIGHT', 0.25),
        recipientWeight: optionalEnvFloat('RECIPIENT_WEIGHT', 0.30),
        timeWeight: optionalEnvFloat('TIME_WEIGHT', 0.10),
        deviceWeight: optionalEnvFloat('DEVICE_WEIGHT', 0.20),
    },

    // Analysis configuration
    analysis: {
        processingTimeoutMs: optionalEnvInt('ANALYSIS_TIMEOUT_MS', 5000),
        userHistoryLimit: optionalEnvInt('USER_HISTORY_LIMIT', 100),
        historyRefreshIntervalMs: optionalEnvInt('HISTORY_REFRESH_INTERVAL', 3600000), // 1 hour

        // Velocity thresholds
        velocity: {
            maxTransfersPerFiveMin: optionalEnvInt('VELOCITY_MAX_5MIN', 3),
            maxTransfersPerHour: optionalEnvInt('VELOCITY_MAX_HOUR', 10),
            maxTransfersPerDay: optionalEnvInt('VELOCITY_MAX_DAY', 50),
        },

        // Amount analysis
        amount: {
            unusualMultiplier: optionalEnvFloat('AMOUNT_UNUSUAL_MULTIPLIER', 5.0),
            largeTransferMin: optionalEnvFloat('LARGE_TRANSFER_MIN', 10000),
        },

        // Geographic analysis
        geographic: {
            impossibleTravelHours: optionalEnvFloat('IMPOSSIBLE_TRAVEL_HOURS', 2.0),
            maxReasonableSpeedKmH: optionalEnvFloat('MAX_TRAVEL_SPEED_KMH', 900), // Airplane speed
        },

        // Recipient analysis
        recipient: {
            newRecipientDays: optionalEnvInt('NEW_RECIPIENT_DAYS', 30),
            trustedRecipientMinTransfers: optionalEnvInt('TRUSTED_RECIPIENT_MIN', 5),
        },
    },

    // Cache TTLs (in seconds)
    cache: {
        userRiskScoreTTL: optionalEnvInt('CACHE_USER_RISK_TTL', 3600), // 1 hour
        blocklistTTL: optionalEnvInt('CACHE_BLOCKLIST_TTL', 3600), // 1 hour
        userHistoryTTL: optionalEnvInt('CACHE_USER_HISTORY_TTL', 1800), // 30 min
        deviceTTL: optionalEnvInt('CACHE_DEVICE_TTL', 86400), // 24 hours
        analysisResultTTL: optionalEnvInt('CACHE_ANALYSIS_TTL', 300), // 5 min
    },

    // Security
    security: {
        fieldEncryptionKey: requireEnv('FIELD_ENCRYPTION_KEY'),
        enableInputValidation: optionalEnvBool('ENABLE_INPUT_VALIDATION', true),
        maxRequestSize: optionalEnvInt('MAX_REQUEST_SIZE', 10240), // 10KB
    },

    // Logging
    logging: {
        level: optionalEnv('LOG_LEVEL', 'info'),
        format: optionalEnv('LOG_FORMAT', 'json'),
        sensitiveFieldMasking: optionalEnvBool('LOG_MASK_SENSITIVE', true),
    },

    // Metrics and monitoring
    metrics: {
        enabled: optionalEnvBool('METRICS_ENABLED', true),
        port: optionalEnvInt('METRICS_PORT', 9090),
        collectDefaultMetrics: optionalEnvBool('COLLECT_DEFAULT_METRICS', true),
    },

    // Helper methods
    isProduction: (): boolean => config.nodeEnv === 'production',
    isDevelopment: (): boolean => config.nodeEnv === 'development',
};

export type Config = typeof config;
