import { Model, DataTypes, Optional } from 'sequelize';
import { sequelize } from './index';

/**
 * ConfirmedFraud model attributes
 */
interface ConfirmedFraudAttributes {
    id: string;
    transactionId: string;
    analysisId: string;
    userId: string;
    amount: number;
    currency: string;
    fraudType: string;
    confirmedBy: string;
    confirmationSource: 'USER_REPORT' | 'ANALYST_REVIEW' | 'CHARGEBACK' | 'LAW_ENFORCEMENT' | 'AUTOMATED';
    originalFraudScore: number;
    description: string;
    evidence?: Record<string, unknown>;
    recoveryAmount?: number;
    recoveryStatus?: 'PENDING' | 'PARTIAL' | 'FULL' | 'FAILED' | 'NOT_APPLICABLE';
    reportedToAuthorities: boolean;
    authoritiesReportId?: string;
    usedForTraining: boolean;
    trainedModelVersion?: string;
    metadata?: Record<string, unknown>;
    createdAt: Date;
    updatedAt: Date;
}

interface ConfirmedFraudCreationAttributes extends Optional<ConfirmedFraudAttributes, 'id' | 'createdAt' | 'updatedAt'> { }

/**
 * ConfirmedFraud Model
 * Stores confirmed fraud cases for model retraining and regulatory compliance
 * Retention: Permanent (used for ML model training)
 */
export class ConfirmedFraud extends Model<ConfirmedFraudAttributes, ConfirmedFraudCreationAttributes> implements ConfirmedFraudAttributes {
    declare id: string;
    declare transactionId: string;
    declare analysisId: string;
    declare userId: string;
    declare amount: number;
    declare currency: string;
    declare fraudType: string;
    declare confirmedBy: string;
    declare confirmationSource: 'USER_REPORT' | 'ANALYST_REVIEW' | 'CHARGEBACK' | 'LAW_ENFORCEMENT' | 'AUTOMATED';
    declare originalFraudScore: number;
    declare description: string;
    declare evidence?: Record<string, unknown>;
    declare recoveryAmount?: number;
    declare recoveryStatus?: 'PENDING' | 'PARTIAL' | 'FULL' | 'FAILED' | 'NOT_APPLICABLE';
    declare reportedToAuthorities: boolean;
    declare authoritiesReportId?: string;
    declare usedForTraining: boolean;
    declare trainedModelVersion?: string;
    declare metadata?: Record<string, unknown>;
    declare readonly createdAt: Date;
    declare readonly updatedAt: Date;

    /**
     * Mark as used for training
     */
    async markAsTrainingData(modelVersion: string): Promise<void> {
        this.usedForTraining = true;
        this.trainedModelVersion = modelVersion;
        await this.save();
    }
}

ConfirmedFraud.init(
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
        },
        analysisId: {
            type: DataTypes.UUID,
            allowNull: false,
            field: 'analysis_id',
        },
        userId: {
            type: DataTypes.UUID,
            allowNull: false,
            field: 'user_id',
        },
        amount: {
            type: DataTypes.DECIMAL(15, 2),
            allowNull: false,
        },
        currency: {
            type: DataTypes.STRING(3),
            allowNull: false,
        },
        fraudType: {
            type: DataTypes.STRING(100),
            allowNull: false,
            field: 'fraud_type',
            comment: 'Category of fraud detected',
        },
        confirmedBy: {
            type: DataTypes.STRING(255),
            allowNull: false,
            field: 'confirmed_by',
        },
        confirmationSource: {
            type: DataTypes.ENUM('USER_REPORT', 'ANALYST_REVIEW', 'CHARGEBACK', 'LAW_ENFORCEMENT', 'AUTOMATED'),
            allowNull: false,
            field: 'confirmation_source',
        },
        originalFraudScore: {
            type: DataTypes.FLOAT,
            allowNull: false,
            field: 'original_fraud_score',
            comment: 'Fraud score when transaction was processed',
        },
        description: {
            type: DataTypes.TEXT,
            allowNull: false,
        },
        evidence: {
            type: DataTypes.JSONB,
            allowNull: true,
        },
        recoveryAmount: {
            type: DataTypes.DECIMAL(15, 2),
            allowNull: true,
            field: 'recovery_amount',
        },
        recoveryStatus: {
            type: DataTypes.ENUM('PENDING', 'PARTIAL', 'FULL', 'FAILED', 'NOT_APPLICABLE'),
            allowNull: true,
            field: 'recovery_status',
        },
        reportedToAuthorities: {
            type: DataTypes.BOOLEAN,
            allowNull: false,
            defaultValue: false,
            field: 'reported_to_authorities',
        },
        authoritiesReportId: {
            type: DataTypes.STRING(100),
            allowNull: true,
            field: 'authorities_report_id',
        },
        usedForTraining: {
            type: DataTypes.BOOLEAN,
            allowNull: false,
            defaultValue: false,
            field: 'used_for_training',
        },
        trainedModelVersion: {
            type: DataTypes.STRING(50),
            allowNull: true,
            field: 'trained_model_version',
        },
        metadata: {
            type: DataTypes.JSONB,
            allowNull: true,
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
    },
    {
        sequelize,
        tableName: 'confirmed_fraud',
        indexes: [
            { fields: ['transaction_id'], unique: true },
            { fields: ['user_id'] },
            { fields: ['fraud_type'] },
            { fields: ['confirmation_source'] },
            { fields: ['used_for_training'] },
            { fields: ['created_at'] },
            { fields: ['used_for_training', 'created_at'] },
        ],
    }
);
