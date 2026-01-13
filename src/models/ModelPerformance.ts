import { Model, DataTypes, Optional } from 'sequelize';
import { sequelize } from './index';

/**
 * ModelPerformance model attributes
 */
interface ModelPerformanceAttributes {
    id: string;
    modelVersion: string;
    date: Date;
    totalAnalyses: number;
    truePositives: number;
    falsePositives: number;
    trueNegatives: number;
    falseNegatives: number;
    accuracy: number;
    precision: number;
    recall: number;
    f1Score: number;
    falsePositiveRate: number;
    truePositiveRate: number;
    avgInferenceTimeMs: number;
    p50InferenceTimeMs: number;
    p99InferenceTimeMs: number;
    avgFraudScore: number;
    approvedCount: number;
    suspiciousCount: number;
    rejectedCount: number;
    manualReviewCount: number;
    notes?: string;
    createdAt: Date;
    updatedAt: Date;
}

interface ModelPerformanceCreationAttributes extends Optional<ModelPerformanceAttributes, 'id' | 'createdAt' | 'updatedAt'> { }

/**
 * ModelPerformance Model
 * Tracks ML model accuracy metrics over time for monitoring and alerting
 * Retention: Last 5 versions + historical daily metrics
 */
export class ModelPerformance extends Model<ModelPerformanceAttributes, ModelPerformanceCreationAttributes> implements ModelPerformanceAttributes {
    declare id: string;
    declare modelVersion: string;
    declare date: Date;
    declare totalAnalyses: number;
    declare truePositives: number;
    declare falsePositives: number;
    declare trueNegatives: number;
    declare falseNegatives: number;
    declare accuracy: number;
    declare precision: number;
    declare recall: number;
    declare f1Score: number;
    declare falsePositiveRate: number;
    declare truePositiveRate: number;
    declare avgInferenceTimeMs: number;
    declare p50InferenceTimeMs: number;
    declare p99InferenceTimeMs: number;
    declare avgFraudScore: number;
    declare approvedCount: number;
    declare suspiciousCount: number;
    declare rejectedCount: number;
    declare manualReviewCount: number;
    declare notes?: string;
    declare readonly createdAt: Date;
    declare readonly updatedAt: Date;
}

ModelPerformance.init(
    {
        id: {
            type: DataTypes.UUID,
            defaultValue: DataTypes.UUIDV4,
            primaryKey: true,
        },
        modelVersion: {
            type: DataTypes.STRING(50),
            allowNull: false,
            field: 'model_version',
        },
        date: {
            type: DataTypes.DATEONLY,
            allowNull: false,
        },
        totalAnalyses: {
            type: DataTypes.INTEGER,
            allowNull: false,
            field: 'total_analyses',
        },
        truePositives: {
            type: DataTypes.INTEGER,
            allowNull: false,
            field: 'true_positives',
        },
        falsePositives: {
            type: DataTypes.INTEGER,
            allowNull: false,
            field: 'false_positives',
        },
        trueNegatives: {
            type: DataTypes.INTEGER,
            allowNull: false,
            field: 'true_negatives',
        },
        falseNegatives: {
            type: DataTypes.INTEGER,
            allowNull: false,
            field: 'false_negatives',
        },
        accuracy: {
            type: DataTypes.FLOAT,
            allowNull: false,
        },
        precision: {
            type: DataTypes.FLOAT,
            allowNull: false,
        },
        recall: {
            type: DataTypes.FLOAT,
            allowNull: false,
        },
        f1Score: {
            type: DataTypes.FLOAT,
            allowNull: false,
            field: 'f1_score',
        },
        falsePositiveRate: {
            type: DataTypes.FLOAT,
            allowNull: false,
            field: 'false_positive_rate',
        },
        truePositiveRate: {
            type: DataTypes.FLOAT,
            allowNull: false,
            field: 'true_positive_rate',
        },
        avgInferenceTimeMs: {
            type: DataTypes.FLOAT,
            allowNull: false,
            field: 'avg_inference_time_ms',
        },
        p50InferenceTimeMs: {
            type: DataTypes.FLOAT,
            allowNull: false,
            field: 'p50_inference_time_ms',
        },
        p99InferenceTimeMs: {
            type: DataTypes.FLOAT,
            allowNull: false,
            field: 'p99_inference_time_ms',
        },
        avgFraudScore: {
            type: DataTypes.FLOAT,
            allowNull: false,
            field: 'avg_fraud_score',
        },
        approvedCount: {
            type: DataTypes.INTEGER,
            allowNull: false,
            field: 'approved_count',
        },
        suspiciousCount: {
            type: DataTypes.INTEGER,
            allowNull: false,
            field: 'suspicious_count',
        },
        rejectedCount: {
            type: DataTypes.INTEGER,
            allowNull: false,
            field: 'rejected_count',
        },
        manualReviewCount: {
            type: DataTypes.INTEGER,
            allowNull: false,
            field: 'manual_review_count',
        },
        notes: {
            type: DataTypes.TEXT,
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
        tableName: 'model_performance',
        indexes: [
            { fields: ['model_version', 'date'], unique: true },
            { fields: ['date'] },
            { fields: ['model_version'] },
            { fields: ['false_positive_rate'] },
            { fields: ['true_positive_rate'] },
        ],
    }
);
