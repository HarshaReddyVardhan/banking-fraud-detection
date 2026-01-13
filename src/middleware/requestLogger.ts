import winston from 'winston';
import { v4 as uuidv4 } from 'uuid';
import { Request, Response, NextFunction } from 'express';
import { config } from '../config/config';

// Sensitive fields to redact from logs
const SENSITIVE_FIELDS = [
    'password',
    'token',
    'accessToken',
    'refreshToken',
    'authorization',
    'cookie',
    'apiKey',
    'secret',
    'ssn',
    'socialSecurityNumber',
    'cardNumber',
    'cvv',
    'encryptionKey',
    'privateKey',
];

// Redact sensitive data from objects
function redactSensitiveData(obj: unknown): unknown {
    if (typeof obj !== 'object' || obj === null) {
        return obj;
    }

    if (Array.isArray(obj)) {
        return obj.map(item => redactSensitiveData(item));
    }

    const result: Record<string, unknown> = {};
    for (const [key, value] of Object.entries(obj)) {
        const lowerKey = key.toLowerCase();
        if (SENSITIVE_FIELDS.some(field => lowerKey.includes(field.toLowerCase()))) {
            result[key] = '[REDACTED]';
        } else if (typeof value === 'object' && value !== null) {
            result[key] = redactSensitiveData(value);
        } else {
            result[key] = value;
        }
    }
    return result;
}

// Mask partial sensitive data (e.g., card numbers, SSN)
function maskSensitiveValue(value: string, visibleChars: number = 4): string {
    if (value.length <= visibleChars) {
        return '*'.repeat(value.length);
    }
    return '*'.repeat(value.length - visibleChars) + value.slice(-visibleChars);
}

// Custom log format for structured logging
const logFormat = winston.format.combine(
    winston.format.timestamp({ format: 'YYYY-MM-DD HH:mm:ss.SSS' }),
    winston.format.errors({ stack: true }),
    winston.format.metadata({ fillExcept: ['message', 'level', 'timestamp'] }),
    config.logging.format === 'json'
        ? winston.format.json()
        : winston.format.printf(({ level, message, timestamp, metadata }) => {
            const meta = Object.keys(metadata as object).length
                ? ` ${JSON.stringify(metadata)}`
                : '';
            return `${timestamp} [${level.toUpperCase()}]: ${message}${meta}`;
        })
);

// Create the logger
export const logger = winston.createLogger({
    level: config.logging.level,
    format: logFormat,
    defaultMeta: { service: config.serviceName },
    transports: [
        // Console transport
        new winston.transports.Console({
            handleExceptions: true,
            handleRejections: true,
        }),
        // File transport for errors (production)
        ...(config.isProduction()
            ? [
                new winston.transports.File({
                    filename: 'logs/error.log',
                    level: 'error',
                    maxsize: 10 * 1024 * 1024, // 10MB
                    maxFiles: 10,
                }),
                new winston.transports.File({
                    filename: 'logs/combined.log',
                    maxsize: 10 * 1024 * 1024,
                    maxFiles: 20,
                }),
                new winston.transports.File({
                    filename: 'logs/fraud-analysis.log',
                    maxsize: 50 * 1024 * 1024, // 50MB for analysis logs
                    maxFiles: 30,
                }),
            ]
            : []),
    ],
    exceptionHandlers: [
        new winston.transports.File({ filename: 'logs/exceptions.log' }),
    ],
    rejectionHandlers: [
        new winston.transports.File({ filename: 'logs/rejections.log' }),
    ],
});

// Fraud-specific logging functions
export const fraudLogger = {
    analysisStarted: (transactionId: string, userId: string, correlationId?: string) => {
        logger.info('Fraud analysis started', {
            event: 'fraud.analysis.started',
            transactionId,
            userId,
            correlationId,
        });
    },

    analysisCompleted: (
        transactionId: string,
        userId: string,
        score: number,
        decision: string,
        analysisTimeMs: number,
        correlationId?: string
    ) => {
        logger.info('Fraud analysis completed', {
            event: 'fraud.analysis.completed',
            transactionId,
            userId,
            score,
            decision,
            analysisTimeMs,
            correlationId,
        });
    },

    analysisError: (transactionId: string, error: unknown, correlationId?: string) => {
        logger.error('Fraud analysis failed', {
            event: 'fraud.analysis.error',
            transactionId,
            correlationId,
            error: config.logging.sensitiveFieldMasking ? redactSensitiveData(error) : error,
        });
    },

    fraudDetected: (
        transactionId: string,
        userId: string,
        score: number,
        reasons: string[],
        correlationId?: string
    ) => {
        logger.warn('Fraud detected', {
            event: 'fraud.detected',
            transactionId,
            userId,
            score,
            reasons,
            correlationId,
            severity: 'HIGH',
        });
    },

    suspiciousActivity: (
        transactionId: string,
        userId: string,
        score: number,
        reasons: string[],
        correlationId?: string
    ) => {
        logger.warn('Suspicious activity detected - manual review required', {
            event: 'fraud.suspicious',
            transactionId,
            userId,
            score,
            reasons,
            correlationId,
            severity: 'MEDIUM',
        });
    },

    manualReviewCreated: (analysisId: string, transactionId: string, priority: string) => {
        logger.info('Manual review created', {
            event: 'fraud.review.created',
            analysisId,
            transactionId,
            priority,
        });
    },

    manualReviewCompleted: (
        analysisId: string,
        transactionId: string,
        reviewerId: string,
        decision: string
    ) => {
        logger.info('Manual review completed', {
            event: 'fraud.review.completed',
            analysisId,
            transactionId,
            reviewerId,
            decision,
        });
    },

    mlModelLoaded: (version: string, loadTimeMs: number) => {
        logger.info('ML model loaded', {
            event: 'ml.model.loaded',
            version,
            loadTimeMs,
        });
    },

    mlModelError: (version: string, error: unknown) => {
        logger.error('ML model error', {
            event: 'ml.model.error',
            version,
            error: config.logging.sensitiveFieldMasking ? redactSensitiveData(error) : error,
        });
    },

    mlInference: (transactionId: string, score: number, inferenceTimeMs: number) => {
        logger.debug('ML inference completed', {
            event: 'ml.inference.completed',
            transactionId,
            score,
            inferenceTimeMs,
        });
    },

    velocityViolation: (userId: string, transactionId: string, windowType: string, count: number) => {
        logger.warn('Velocity violation detected', {
            event: 'fraud.velocity.violation',
            userId,
            transactionId,
            windowType,
            count,
        });
    },

    geographicAnomaly: (
        userId: string,
        transactionId: string,
        reason: string,
        details: Record<string, unknown>
    ) => {
        logger.warn('Geographic anomaly detected', {
            event: 'fraud.geographic.anomaly',
            userId,
            transactionId,
            reason,
            ...redactSensitiveData(details),
        });
    },

    blocklistMatch: (type: string, value: string, transactionId: string) => {
        logger.warn('Blocklist match detected', {
            event: 'fraud.blocklist.match',
            type,
            value: maskSensitiveValue(value, 4),
            transactionId,
        });
    },

    auditLog: (action: string, userId: string, details: Record<string, unknown>) => {
        logger.info(`Audit: ${action}`, {
            event: 'audit',
            action,
            userId,
            ...redactSensitiveData(details),
        });
    },
};

// Request logging helper
export function createRequestLogData(
    method: string,
    url: string,
    statusCode: number,
    responseTime: number,
    ip: string,
    correlationId: string
): Record<string, unknown> {
    return {
        event: 'http.request',
        method,
        url: url.split('?')[0], // Remove query params
        statusCode,
        responseTime: `${responseTime}ms`,
        ip,
        correlationId,
    };
}

export { redactSensitiveData, maskSensitiveValue };

/**
 * Express middleware for request logging
 */
export function requestLoggerMiddleware(req: Request, res: Response, next: NextFunction): void {
    const start = Date.now();
    const correlationId = (req.headers['x-correlation-id'] as string) || uuidv4();
    (req as any).correlationId = correlationId;

    res.on('finish', () => {
        const duration = Date.now() - start;
        const logData = createRequestLogData(
            req.method,
            req.originalUrl || req.url,
            res.statusCode,
            duration,
            req.ip || req.socket.remoteAddress || 'unknown',
            correlationId
        );
        logger.info('HTTP Request', logData);
    });

    next();
}

