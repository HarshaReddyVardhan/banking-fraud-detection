import { Model, DataTypes, Optional } from 'sequelize';
import { sequelize } from './index';

/**
 * Blocklist entry types
 */
export type BlocklistType = 'ACCOUNT' | 'DEVICE' | 'IP' | 'RECIPIENT' | 'EMAIL' | 'PHONE';

/**
 * FraudBlocklist model attributes
 */
interface FraudBlocklistAttributes {
    id: string;
    type: BlocklistType;
    value: string;
    valueHash: string;
    reason: string;
    addedBy: string;
    severity: 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL';
    source: string;
    expiresAt?: Date;
    isActive: boolean;
    matchCount: number;
    lastMatchAt?: Date;
    metadata?: Record<string, unknown>;
    createdAt: Date;
    updatedAt: Date;
    deletedAt?: Date;
}

interface FraudBlocklistCreationAttributes extends Optional<FraudBlocklistAttributes, 'id' | 'createdAt' | 'updatedAt' | 'matchCount'> { }

/**
 * FraudBlocklist Model
 * Maintains list of known fraudulent accounts, devices, IPs, and recipients
 * Entries remain until manually removed for permanent blocking
 */
export class FraudBlocklist extends Model<FraudBlocklistAttributes, FraudBlocklistCreationAttributes> implements FraudBlocklistAttributes {
    declare id: string;
    declare type: BlocklistType;
    declare value: string;
    declare valueHash: string;
    declare reason: string;
    declare addedBy: string;
    declare severity: 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL';
    declare source: string;
    declare expiresAt?: Date;
    declare isActive: boolean;
    declare matchCount: number;
    declare lastMatchAt?: Date;
    declare metadata?: Record<string, unknown>;
    declare readonly createdAt: Date;
    declare readonly updatedAt: Date;
    declare readonly deletedAt?: Date;

    /**
     * Increment match count when blocklist entry is triggered
     */
    async recordMatch(): Promise<void> {
        this.matchCount += 1;
        this.lastMatchAt = new Date();
        await this.save();
    }
}

FraudBlocklist.init(
    {
        id: {
            type: DataTypes.UUID,
            defaultValue: DataTypes.UUIDV4,
            primaryKey: true,
        },
        type: {
            type: DataTypes.ENUM('ACCOUNT', 'DEVICE', 'IP', 'RECIPIENT', 'EMAIL', 'PHONE'),
            allowNull: false,
            comment: 'Type of blocked entity',
        },
        value: {
            type: DataTypes.STRING(500),
            allowNull: false,
            comment: 'Blocked value (may be encrypted for sensitive data)',
        },
        valueHash: {
            type: DataTypes.STRING(64),
            allowNull: false,
            field: 'value_hash',
            comment: 'SHA-256 hash for fast lookup without decryption',
        },
        reason: {
            type: DataTypes.TEXT,
            allowNull: false,
            comment: 'Reason for blocking',
        },
        addedBy: {
            type: DataTypes.STRING(255),
            allowNull: false,
            field: 'added_by',
            comment: 'User or system that added the entry',
        },
        severity: {
            type: DataTypes.ENUM('LOW', 'MEDIUM', 'HIGH', 'CRITICAL'),
            allowNull: false,
            defaultValue: 'HIGH',
            comment: 'Severity level for prioritization',
        },
        source: {
            type: DataTypes.STRING(100),
            allowNull: false,
            comment: 'Source of blocklist entry (manual, automated, external)',
        },
        expiresAt: {
            type: DataTypes.DATE,
            allowNull: true,
            field: 'expires_at',
            comment: 'Optional expiration for temporary blocks',
        },
        isActive: {
            type: DataTypes.BOOLEAN,
            allowNull: false,
            defaultValue: true,
            field: 'is_active',
        },
        matchCount: {
            type: DataTypes.INTEGER,
            allowNull: false,
            defaultValue: 0,
            field: 'match_count',
            comment: 'Number of times this entry has been matched',
        },
        lastMatchAt: {
            type: DataTypes.DATE,
            allowNull: true,
            field: 'last_match_at',
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
        tableName: 'fraud_blocklist',
        paranoid: true,
        indexes: [
            { fields: ['value_hash'] },
            { fields: ['type', 'value_hash'] },
            { fields: ['type', 'is_active'] },
            { fields: ['is_active'] },
            { fields: ['expires_at'] },
            { fields: ['severity'] },
            { fields: ['created_at'] },
        ],
    }
);
