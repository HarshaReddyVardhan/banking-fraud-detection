import { Model, DataTypes, Optional } from 'sequelize';
import { sequelize } from './index';
import { ReviewStatus } from '../types';

/**
 * ManualReview model attributes
 */
interface ManualReviewAttributes {
    id: string;
    analysisId: string;
    transactionId: string;
    userId: string;
    fraudScore: number;
    priority: 'LOW' | 'MEDIUM' | 'HIGH' | 'URGENT';
    status: ReviewStatus;
    assignedTo?: string;
    riskFactors: Record<string, unknown>[];
    transactionDetails: Record<string, unknown>;
    userHistory: Record<string, unknown>;
    reviewerNotes?: string;
    decision?: 'APPROVED' | 'REJECTED' | 'ESCALATED' | 'INFO_REQUESTED';
    decisionReason?: string;
    decisionAt?: Date;
    escalatedTo?: string;
    escalationReason?: string;
    infoRequestDetails?: string;
    turnaroundTimeMs?: number;
    metadata?: Record<string, unknown>;
    createdAt: Date;
    updatedAt: Date;
    deletedAt?: Date;
}

interface ManualReviewCreationAttributes extends Optional<ManualReviewAttributes, 'id' | 'createdAt' | 'updatedAt'> { }

/**
 * ManualReview Model
 * Tracks manual fraud review workflow for suspicious transactions
 * Target turnaround: <30 minutes
 */
export class ManualReview extends Model<ManualReviewAttributes, ManualReviewCreationAttributes> implements ManualReviewAttributes {
    declare id: string;
    declare analysisId: string;
    declare transactionId: string;
    declare userId: string;
    declare fraudScore: number;
    declare priority: 'LOW' | 'MEDIUM' | 'HIGH' | 'URGENT';
    declare status: ReviewStatus;
    declare assignedTo?: string;
    declare riskFactors: Record<string, unknown>[];
    declare transactionDetails: Record<string, unknown>;
    declare userHistory: Record<string, unknown>;
    declare reviewerNotes?: string;
    declare decision?: 'APPROVED' | 'REJECTED' | 'ESCALATED' | 'INFO_REQUESTED';
    declare decisionReason?: string;
    declare decisionAt?: Date;
    declare escalatedTo?: string;
    declare escalationReason?: string;
    declare infoRequestDetails?: string;
    declare turnaroundTimeMs?: number;
    declare metadata?: Record<string, unknown>;
    declare readonly createdAt: Date;
    declare readonly updatedAt: Date;
    declare readonly deletedAt?: Date;

    /**
     * Complete the review with a decision
     */
    async completeReview(
        _reviewerId: string,
        decision: 'APPROVED' | 'REJECTED' | 'ESCALATED' | 'INFO_REQUESTED',
        reason: string,
        notes?: string
    ): Promise<void> {
        this.status = decision === 'ESCALATED' ? 'ESCALATED' :
            decision === 'INFO_REQUESTED' ? 'INFO_REQUESTED' :
                decision === 'APPROVED' ? 'APPROVED' : 'REJECTED';
        this.decision = decision;
        this.decisionReason = reason;
        this.reviewerNotes = notes;
        this.decisionAt = new Date();
        this.turnaroundTimeMs = this.decisionAt.getTime() - this.createdAt.getTime();
        await this.save();
    }

    /**
     * Escalate the review
     */
    async escalate(escalatedTo: string, reason: string): Promise<void> {
        this.status = 'ESCALATED';
        this.escalatedTo = escalatedTo;
        this.escalationReason = reason;
        await this.save();
    }

    /**
     * Assign review to analyst
     */
    async assignTo(analystId: string): Promise<void> {
        this.assignedTo = analystId;
        this.status = 'IN_PROGRESS';
        await this.save();
    }
}

ManualReview.init(
    {
        id: {
            type: DataTypes.UUID,
            defaultValue: DataTypes.UUIDV4,
            primaryKey: true,
        },
        analysisId: {
            type: DataTypes.UUID,
            allowNull: false,
            field: 'analysis_id',
            comment: 'Reference to fraud analysis',
        },
        transactionId: {
            type: DataTypes.UUID,
            allowNull: false,
            field: 'transaction_id',
        },
        userId: {
            type: DataTypes.UUID,
            allowNull: false,
            field: 'user_id',
        },
        fraudScore: {
            type: DataTypes.FLOAT,
            allowNull: false,
            field: 'fraud_score',
        },
        priority: {
            type: DataTypes.ENUM('LOW', 'MEDIUM', 'HIGH', 'URGENT'),
            allowNull: false,
            defaultValue: 'MEDIUM',
        },
        status: {
            type: DataTypes.ENUM('PENDING', 'IN_PROGRESS', 'APPROVED', 'REJECTED', 'ESCALATED', 'INFO_REQUESTED'),
            allowNull: false,
            defaultValue: 'PENDING',
        },
        assignedTo: {
            type: DataTypes.UUID,
            allowNull: true,
            field: 'assigned_to',
        },
        riskFactors: {
            type: DataTypes.JSONB,
            allowNull: false,
            field: 'risk_factors',
        },
        transactionDetails: {
            type: DataTypes.JSONB,
            allowNull: false,
            field: 'transaction_details',
        },
        userHistory: {
            type: DataTypes.JSONB,
            allowNull: false,
            field: 'user_history',
        },
        reviewerNotes: {
            type: DataTypes.TEXT,
            allowNull: true,
            field: 'reviewer_notes',
        },
        decision: {
            type: DataTypes.ENUM('APPROVED', 'REJECTED', 'ESCALATED', 'INFO_REQUESTED'),
            allowNull: true,
        },
        decisionReason: {
            type: DataTypes.TEXT,
            allowNull: true,
            field: 'decision_reason',
        },
        decisionAt: {
            type: DataTypes.DATE,
            allowNull: true,
            field: 'decision_at',
        },
        escalatedTo: {
            type: DataTypes.UUID,
            allowNull: true,
            field: 'escalated_to',
        },
        escalationReason: {
            type: DataTypes.TEXT,
            allowNull: true,
            field: 'escalation_reason',
        },
        infoRequestDetails: {
            type: DataTypes.TEXT,
            allowNull: true,
            field: 'info_request_details',
        },
        turnaroundTimeMs: {
            type: DataTypes.INTEGER,
            allowNull: true,
            field: 'turnaround_time_ms',
            comment: 'Time from creation to decision in milliseconds',
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
        deletedAt: {
            type: DataTypes.DATE,
            allowNull: true,
            field: 'deleted_at',
        },
    },
    {
        sequelize,
        tableName: 'manual_reviews',
        paranoid: true,
        indexes: [
            { fields: ['analysis_id'], unique: true },
            { fields: ['transaction_id'] },
            { fields: ['user_id'] },
            { fields: ['status'] },
            { fields: ['priority'] },
            { fields: ['assigned_to'] },
            { fields: ['created_at'] },
            { fields: ['status', 'priority', 'created_at'] },
            { fields: ['assigned_to', 'status'] },
        ],
    }
);
