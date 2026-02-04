/**
 * Fraud Detection Service - Type Definitions
 * Banking-grade type safety for fraud analysis operations
 */

/**
 * Risk decision made by the fraud detection system
 */
export type RiskDecision = 'APPROVE' | 'SUSPICIOUS' | 'REJECT';

/**
 * Confidence level of the ML model prediction
 */
export type ConfidenceLevel = 'HIGH' | 'MEDIUM' | 'LOW';

/**
 * Status of a fraud analysis
 */
export type AnalysisStatus = 'PENDING' | 'COMPLETED' | 'FAILED' | 'TIMEOUT';

/**
 * Manual review status
 */
export type ReviewStatus = 'PENDING' | 'IN_PROGRESS' | 'APPROVED' | 'REJECTED' | 'ESCALATED' | 'INFO_REQUESTED';

/**
 * Types of fraud detection methods
 */
export type FraudDetectionMethod =
    | 'VELOCITY'
    | 'GEOGRAPHIC'
    | 'AMOUNT'
    | 'RECIPIENT'
    | 'TIME'
    | 'DEVICE'
    | 'ML_MODEL';

/**
 * Incoming transaction event from Kafka
 */
export interface TransactionCreatedEvent {
    eventType: 'TransactionCreated';
    eventId: string;
    timestamp: string;
    version: string;
    correlationId?: string;
    payload: {
        transactionId: string;
        userId: string;
        sourceAccountId: string;
        destinationAccountId: string;
        recipientId: string;
        amount: number;
        currency: string;
        description?: string;
        geographic?: {
            ip: string;
            latitude?: number;
            longitude?: number;
            country?: string;
            city?: string;
        };
        device?: {
            fingerprint: string;
            userAgent?: string;
            deviceId?: string;
            deviceType?: string;
        };
        metadata?: Record<string, unknown>;
    };
}

/**
 * Risk factor identified during analysis
 */
export interface RiskFactor {
    method: FraudDetectionMethod;
    score: number;
    weight: number;
    contributedScore: number;
    reason: string;
    details?: Record<string, unknown>;
}

/**
 * Complete fraud analysis result
 */
export interface FraudAnalysisResult {
    transactionId: string;
    userId: string;
    score: number;
    decision: RiskDecision;
    confidence: ConfidenceLevel;
    status: AnalysisStatus;
    riskFactors: RiskFactor[];
    modelVersion: string;
    analysisTimeMs: number;
    timestamp: string;
    requiresManualReview: boolean;
    metadata?: {
        velocityScore?: number;
        geographicScore?: number;
        amountScore?: number;
        recipientScore?: number;
        timeScore?: number;
        deviceScore?: number;
        mlScore?: number;
    };
}

/**
 * Manual review request
 */
export interface ManualReviewRequest {
    analysisId: string;
    transactionId: string;
    userId: string;
    fraudScore: number;
    riskFactors: RiskFactor[];
    transactionDetails: {
        amount: number;
        currency: string;
        recipientId: string;
        description?: string;
    };
    userHistory: {
        previousTransactionCount: number;
        averageTransactionAmount: number;
        accountAge: number;
        previousFraudFlags: number;
    };
    assignedTo?: string;
    priority: 'HIGH' | 'MEDIUM' | 'LOW';
    createdAt: string;
}

/**
 * Manual review decision
 */
export interface ManualReviewDecision {
    analysisId: string;
    transactionId: string;
    reviewerId: string;
    decision: 'APPROVED' | 'REJECTED' | 'ESCALATED' | 'INFO_REQUESTED';
    reason: string;
    notes?: string;
    timestamp: string;
}

/**
 * User transaction history for analysis
 */
export interface UserTransactionHistory {
    userId: string;
    transactions: Array<{
        transactionId: string;
        amount: number;
        recipientId: string;
        timestamp: string;
        status: string;
        fraudScore?: number;
        country?: string;
        deviceFingerprint?: string;
    }>;
    statistics: {
        totalTransactions: number;
        averageAmount: number;
        maxAmount: number;
        minAmount: number;
        standardDeviation: number;
        uniqueRecipients: number;
        uniqueCountries: number;
        uniqueDevices: number;
        accountCreatedAt: string;
        lastTransactionAt?: string;
    };
    cachedAt: string;
}

/**
 * Device information for analysis
 */
export interface DeviceInfo {
    fingerprint: string;
    userId: string;
    isKnown: boolean;
    firstSeen?: string;
    lastSeen?: string;
    transactionCount: number;
    trustScore: number;
    isFlagged: boolean;
    flagReason?: string;
}

/**
 * Recipient information for analysis
 */
export interface RecipientInfo {
    recipientId: string;
    isBlocked: boolean;
    blockReason?: string;
    isNew: boolean;
    firstTransactionAt?: string;
    lastTransactionAt?: string;
    totalTransactions: number;
    totalAmount: number;
    riskScore: number;
    accountAge?: number;
    isVerified: boolean;
    country?: string;
}

/**
 * Geographic location data
 */
export interface GeoLocation {
    ip?: string;
    country: string | null;
    city: string | null;
    latitude: number | null;
    longitude: number | null;
    timezone?: string;
}

/**
 * Velocity analysis data
 */
export interface VelocityData {
    transactionsFiveMin: number;
    transactionsOneHour: number;
    transactionsTwentyFourHours: number;
    amountFiveMin: number;
    amountOneHour: number;
    amountTwentyFourHours: number;
    uniqueRecipientsFiveMin: number;
    uniqueRecipientsOneHour: number;
}

/**
 * ML model features for inference
 */
export interface MLFeatures {
    // Velocity features
    txCountFiveMin: number;
    txCountOneHour: number;
    txCountTwentyFourHours: number;
    amountFiveMin: number;
    amountOneHour: number;
    amountTwentyFourHours: number;

    // Amount features
    amount: number;
    amountRatioToAvg: number;
    amountRatioToMax: number;
    amountZScore: number;

    // Geographic features
    isNewCountry: number;
    distanceFromLastTx: number;
    impossibleTravel: number;

    // Time features
    hourOfDay: number;
    dayOfWeek: number;
    isUnusualHour: number;
    timeSinceLastTx: number;

    // Recipient features
    isNewRecipient: number;
    recipientRiskScore: number;
    recipientTxCount: number;

    // Device features
    isNewDevice: number;
    deviceTrustScore: number;

    // User profile features
    accountAge: number;
    totalTxCount: number;
    avgTxAmount: number;
    previousFraudFlags: number;
}

/**
 * Blocklist entry
 */
export interface BlocklistEntry {
    id: string;
    type: 'ACCOUNT' | 'DEVICE' | 'IP' | 'RECIPIENT' | 'EMAIL' | 'PHONE';
    value: string;
    reason: string;
    addedBy: string;
    addedAt: string;
    expiresAt?: string;
    isActive: boolean;
}

/**
 * Fraud event for Kafka publishing
 */
export interface FraudAnalysisEvent {
    eventType: 'FraudAnalysisComplete' | 'FraudSuspected' | 'FraudRejected' | 'ManualReviewRequired';
    eventId: string;
    timestamp: string;
    version: string;
    service: string;
    correlationId?: string;
    payload: FraudAnalysisResult;
}

/**
 * Health check response
 */
export interface HealthCheckResponse {
    status: 'healthy' | 'degraded' | 'unhealthy';
    service: string;
    timestamp: string;
    version: string;
    checks: {
        database: 'up' | 'down';
        redis: 'up' | 'down';
        kafka: 'up' | 'down';
        mlModel: 'loaded' | 'not_loaded' | 'fallback';
    };
    metrics?: {
        analysisLatencyP50?: number;
        analysisLatencyP99?: number;
        analysisCount24h?: number;
        fraudDetectionRate?: number;
        falsePositiveRate?: number;
    };
}
