import { Request, Response, NextFunction } from 'express';
import { logger } from './requestLogger';

/**
 * Custom error class for application errors
 */
export class AppError extends Error {
    public readonly statusCode: number;
    public readonly isOperational: boolean;
    public readonly code: string;

    constructor(
        message: string,
        statusCode: number = 500,
        code: string = 'INTERNAL_ERROR',
        isOperational: boolean = true
    ) {
        super(message);
        this.statusCode = statusCode;
        this.code = code;
        this.isOperational = isOperational;

        Error.captureStackTrace(this, this.constructor);
    }
}

/**
 * Specific error types for fraud detection
 */
export class ValidationError extends AppError {
    constructor(message: string) {
        super(message, 400, 'VALIDATION_ERROR');
    }
}

export class AnalysisTimeoutError extends AppError {
    constructor(transactionId: string) {
        super(`Analysis timeout for transaction: ${transactionId}`, 408, 'ANALYSIS_TIMEOUT');
    }
}

export class ModelLoadError extends AppError {
    constructor(message: string) {
        super(message, 500, 'MODEL_LOAD_ERROR', false);
    }
}

export class BlocklistMatchError extends AppError {
    constructor(type: string, _value: string) {
        super(`Blocklist match: ${type}`, 403, 'BLOCKLIST_MATCH');
    }
}

export class DatabaseError extends AppError {
    constructor(message: string) {
        super(message, 500, 'DATABASE_ERROR', false);
    }
}

export class KafkaError extends AppError {
    constructor(message: string) {
        super(message, 500, 'KAFKA_ERROR', false);
    }
}

export class CacheError extends AppError {
    constructor(message: string) {
        super(message, 500, 'CACHE_ERROR');
    }
}

/**
 * Error response interface
 */
interface ErrorResponse {
    success: false;
    error: {
        code: string;
        message: string;
        timestamp: string;
        correlationId?: string;
    };
}

/**
 * Global error handler middleware
 */
export function errorHandler(
    err: Error,
    req: Request,
    res: Response,
    _next: NextFunction
): void {
    const correlationId = (req as { correlationId?: string }).correlationId;

    // Default error values
    let statusCode = 500;
    let code = 'INTERNAL_ERROR';
    let message = 'An unexpected error occurred';
    let isOperational = false;

    if (err instanceof AppError) {
        statusCode = err.statusCode;
        code = err.code;
        message = err.message;
        isOperational = err.isOperational;
    }

    // Log the error
    if (isOperational) {
        logger.warn('Operational error', {
            code,
            message,
            statusCode,
            correlationId,
            path: req.path,
        });
    } else {
        logger.error('System error', {
            code,
            message: err.message,
            stack: err.stack,
            statusCode,
            correlationId,
            path: req.path,
        });
    }

    // Don't leak internal error details in production
    if (statusCode === 500 && process.env['NODE_ENV'] === 'production') {
        message = 'An unexpected error occurred';
    }

    const errorResponse: ErrorResponse = {
        success: false,
        error: {
            code,
            message,
            timestamp: new Date().toISOString(),
            correlationId,
        },
    };

    res.status(statusCode).json(errorResponse);
}

/**
 * 404 Not Found handler
 */
export function notFoundHandler(
    req: Request,
    _res: Response,
    next: NextFunction
): void {
    const error = new AppError(`Route not found: ${req.method} ${req.path}`, 404, 'NOT_FOUND');
    next(error);
}

/**
 * Async handler wrapper to catch async errors
 */
export function asyncHandler(
    fn: (req: Request, res: Response, next: NextFunction) => Promise<void>
) {
    return (req: Request, res: Response, next: NextFunction) => {
        Promise.resolve(fn(req, res, next)).catch(next);
    };
}
