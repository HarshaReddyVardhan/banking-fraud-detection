import { Model, DataTypes, Optional } from 'sequelize';
import { sequelize } from './index';
import { RiskDecision, ConfidenceLevel, AnalysisStatus, RiskFactor } from '../types';

/**
 * FraudAnalysis model attributes
 */
interface FraudAnalysisAttributes {
    id: string;
    transactionId: string;
    userId: string;
    score: number;
    decision: RiskDecision;
    confidence: ConfidenceLevel;
    status: AnalysisStatus;
    riskFactors: RiskFactor[];
    modelVersion: string;
    analysisTimeMs: number;
    correlationId?: string;
    velocityScore?: number;
    geographicScore?: number;
    amountScore?: number;
    recipientScore?: number;
    timeScore?: number;
    deviceScore?: number;
    mlScore?: number;
    requiresManualReview: boolean;
    reviewId?: string;
    metadata?: Record<string, unknown>;
    createdAt: Date;
    updatedAt: Date;
    deletedAt?: Date;
}

// Creation attributes (id is auto-generated)
interface FraudAnalysisCreationAttributes extends Optional<FraudAnalysisAttributes, 'id' | 'createdAt' | 'updatedAt'> { }

/**
 * FraudAnalysis Model
 * Stores all fraud analysis results for audit trail and regulatory compliance
 * Retention: 7 years per banking regulations
 */
export class FraudAnalysis extends Model<FraudAnalysisAttributes, FraudAnalysisCreationAttributes> implements FraudAnalysisAttributes {
    declare id: string;
    declare transactionId: string;
    declare userId: string;
    declare score: number;
    declare decision: RiskDecision;
    declare confidence: ConfidenceLevel;
    declare status: AnalysisStatus;
    declare riskFactors: RiskFactor[];
    declare modelVersion: string;
    declare analysisTimeMs: number;
    declare correlationId?: string;
    declare velocityScore?: number;
    declare geographicScore?: number;
    declare amountScore?: number;
    declare recipientScore?: number;
    declare timeScore?: number;
    declare deviceScore?: number;
    declare mlScore?: number;
    declare requiresManualReview: boolean;
    declare reviewId?: string;
    declare metadata?: Record<string, unknown>;
    declare readonly createdAt: Date;
    declare readonly updatedAt: Date;
    declare readonly deletedAt?: Date;
}

FraudAnalysis.init(
    {
        id: {
            type: DataTypes.UUID,
            defaultValue: DataTypes.UUIDV4,
            primaryKey: true,
        },
        transactionId: {
            type: DataTypes.UUID,
            allowNull: false,
            field: 'transaction_id',
            comment: 'Reference to the analyzed transaction',
        },
        userId: {
            type: DataTypes.UUID,
            allowNull: false,
            field: 'user_id',
            comment: 'User who initiated the transaction',
        },
        score: {
            type: DataTypes.FLOAT,
            allowNull: false,
            validate: {
                min: 0.0,
                max: 1.0,
            },
            comment: 'Fraud risk score from 0.0 (safe) to 1.0 (fraudulent)',
        },
        decision: {
            type: DataTypes.ENUM('APPROVE', 'SUSPICIOUS', 'REJECT'),
            allowNull: false,
            comment: 'Final risk decision based on score thresholds',
        },
        confidence: {
            type: DataTypes.ENUM('HIGH', 'MEDIUM', 'LOW'),
            allowNull: false,
            comment: 'ML model confidence level',
        },
        status: {
            type: DataTypes.ENUM('PENDING', 'COMPLETED', 'FAILED', 'TIMEOUT'),
            allowNull: false,
            defaultValue: 'PENDING',
            comment: 'Analysis processing status',
        },
        riskFactors: {
            type: DataTypes.JSONB,
            allowNull: false,
            defaultValue: [],
            field: 'risk_factors',
            comment: 'Detailed breakdown of identified risk factors',
        },
        modelVersion: {
            type: DataTypes.STRING(50),
            allowNull: false,
            field: 'model_version',
            comment: 'ML model version used for analysis',
        },
        analysisTimeMs: {
            type: DataTypes.INTEGER,
            allowNull: false,
            field: 'analysis_time_ms',
            comment: 'Total analysis duration in milliseconds',
        },
        correlationId: {
            type: DataTypes.UUID,
            allowNull: true,
            field: 'correlation_id',
            comment: 'Request correlation ID for distributed tracing',
        },
        velocityScore: {
            type: DataTypes.FLOAT,
            allowNull: true,
            field: 'velocity_score',
        },
        geographicScore: {
            type: DataTypes.FLOAT,
            allowNull: true,
            field: 'geographic_score',
        },
        amountScore: {
            type: DataTypes.FLOAT,
            allowNull: true,
            field: 'amount_score',
        },
        recipientScore: {
            type: DataTypes.FLOAT,
            allowNull: true,
            field: 'recipient_score',
        },
        timeScore: {
            type: DataTypes.FLOAT,
            allowNull: true,
            field: 'time_score',
        },
        deviceScore: {
            type: DataTypes.FLOAT,
            allowNull: true,
            field: 'device_score',
        },
        mlScore: {
            type: DataTypes.FLOAT,
            allowNull: true,
            field: 'ml_score',
        },
        requiresManualReview: {
            type: DataTypes.BOOLEAN,
            allowNull: false,
            defaultValue: false,
            field: 'requires_manual_review',
        },
        reviewId: {
            type: DataTypes.UUID,
            allowNull: true,
            field: 'review_id',
            comment: 'Reference to manual review if required',
        },
        metadata: {
            type: DataTypes.JSONB,
            allowNull: true,
            comment: 'Additional analysis metadata',
        },
        createdAt: {
            type: DataTypes.DATE,
            allowNull: false,
            field: 'created_at',
        },
        updatedAt: {
            type: DataTypes.DATE,
            allowNull: false,
            field: 'updated_at',
        },
        deletedAt: {
            type: DataTypes.DATE,
            allowNull: true,
            field: 'deleted_at',
        },
    },
    {
        sequelize,
        tableName: 'fraud_analyses',
        paranoid: true,
        indexes: [
            { fields: ['transaction_id'], unique: true },
            { fields: ['user_id'] },
            { fields: ['score'] },
            { fields: ['decision'] },
            { fields: ['status'] },
            { fields: ['created_at'] },
            { fields: ['requires_manual_review'] },
            { fields: ['correlation_id'] },
            // Composite index for querying user fraud history
            { fields: ['user_id', 'created_at'] },
            // Composite index for monitoring
            { fields: ['decision', 'created_at'] },
        ],
    }
);
