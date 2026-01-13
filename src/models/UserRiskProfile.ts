import { Model, DataTypes, Optional } from 'sequelize';
import { sequelize } from './index';

/**
 * UserRiskProfile model attributes
 */
interface UserRiskProfileAttributes {
    id: string;
    userId: string;
    baselineRiskScore: number;
    currentRiskScore: number;
    riskLevel: 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL';
    totalTransactions: number;
    averageTransactionAmount: number;
    maxTransactionAmount: number;
    transactionStdDev: number;
    uniqueRecipients: number;
    uniqueCountries: number;
    uniqueDevices: number;
    fraudFlagCount: number;
    lastFraudFlagAt?: Date;
    suspiciousActivityCount: number;
    approvedHighRiskCount: number;
    accountCreatedAt: Date;
    lastTransactionAt?: Date;
    lastAnalyzedAt?: Date;
    preferredHours: number[];
    preferredDays: number[];
    knownCountries: string[];
    knownDevices: string[];
    trustedRecipients: string[];
    isWhitelisted: boolean;
    whitelistReason?: string;
    whitelistExpiresAt?: Date;
    isFlagged: boolean;
    flagReason?: string;
    metadata?: Record<string, unknown>;
    createdAt: Date;
    updatedAt: Date;
}

interface UserRiskProfileCreationAttributes extends Optional<UserRiskProfileAttributes, 'id' | 'createdAt' | 'updatedAt'> { }

/**
 * UserRiskProfile Model
 * Maintains computed risk profile for each user based on their transaction history
 * Cache TTL: 1 hour (refreshed with each new transaction)
 */
export class UserRiskProfile extends Model<UserRiskProfileAttributes, UserRiskProfileCreationAttributes> implements UserRiskProfileAttributes {
    declare id: string;
    declare userId: string;
    declare baselineRiskScore: number;
    declare currentRiskScore: number;
    declare riskLevel: 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL';
    declare totalTransactions: number;
    declare averageTransactionAmount: number;
    declare maxTransactionAmount: number;
    declare transactionStdDev: number;
    declare uniqueRecipients: number;
    declare uniqueCountries: number;
    declare uniqueDevices: number;
    declare fraudFlagCount: number;
    declare lastFraudFlagAt?: Date;
    declare suspiciousActivityCount: number;
    declare approvedHighRiskCount: number;
    declare accountCreatedAt: Date;
    declare lastTransactionAt?: Date;
    declare lastAnalyzedAt?: Date;
    declare preferredHours: number[];
    declare preferredDays: number[];
    declare knownCountries: string[];
    declare knownDevices: string[];
    declare trustedRecipients: string[];
    declare isWhitelisted: boolean;
    declare whitelistReason?: string;
    declare whitelistExpiresAt?: Date;
    declare isFlagged: boolean;
    declare flagReason?: string;
    declare metadata?: Record<string, unknown>;
    declare readonly createdAt: Date;
    declare readonly updatedAt: Date;

    /**
     * Update risk score and level
     */
    async updateRiskScore(score: number): Promise<void> {
        this.currentRiskScore = score;
        this.riskLevel = this.calculateRiskLevel(score);
        this.lastAnalyzedAt = new Date();
        await this.save();
    }

    /**
     * Calculate risk level from score
     */
    private calculateRiskLevel(score: number): 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL' {
        if (score < 0.25) return 'LOW';
        if (score < 0.50) return 'MEDIUM';
        if (score < 0.80) return 'HIGH';
        return 'CRITICAL';
    }

    /**
     * Add a known device
     */
    async addKnownDevice(deviceFingerprint: string): Promise<void> {
        if (!this.knownDevices.includes(deviceFingerprint)) {
            this.knownDevices = [...this.knownDevices, deviceFingerprint];
            this.uniqueDevices = this.knownDevices.length;
            await this.save();
        }
    }

    /**
     * Add a known country
     */
    async addKnownCountry(country: string): Promise<void> {
        if (!this.knownCountries.includes(country)) {
            this.knownCountries = [...this.knownCountries, country];
            this.uniqueCountries = this.knownCountries.length;
            await this.save();
        }
    }

    /**
     * Add a trusted recipient
     */
    async addTrustedRecipient(recipientId: string): Promise<void> {
        if (!this.trustedRecipients.includes(recipientId)) {
            this.trustedRecipients = [...this.trustedRecipients, recipientId];
            this.uniqueRecipients = this.trustedRecipients.length;
            await this.save();
        }
    }

    /**
     * Increment fraud flag count
     */
    async incrementFraudFlag(): Promise<void> {
        this.fraudFlagCount += 1;
        this.lastFraudFlagAt = new Date();
        await this.save();
    }
}

UserRiskProfile.init(
    {
        id: {
            type: DataTypes.UUID,
            defaultValue: DataTypes.UUIDV4,
            primaryKey: true,
        },
        userId: {
            type: DataTypes.UUID,
            allowNull: false,
            unique: true,
            field: 'user_id',
        },
        baselineRiskScore: {
            type: DataTypes.FLOAT,
            allowNull: false,
            defaultValue: 0.1,
            field: 'baseline_risk_score',
        },
        currentRiskScore: {
            type: DataTypes.FLOAT,
            allowNull: false,
            defaultValue: 0.1,
            field: 'current_risk_score',
        },
        riskLevel: {
            type: DataTypes.ENUM('LOW', 'MEDIUM', 'HIGH', 'CRITICAL'),
            allowNull: false,
            defaultValue: 'LOW',
            field: 'risk_level',
        },
        totalTransactions: {
            type: DataTypes.INTEGER,
            allowNull: false,
            defaultValue: 0,
            field: 'total_transactions',
        },
        averageTransactionAmount: {
            type: DataTypes.DECIMAL(15, 2),
            allowNull: false,
            defaultValue: 0,
            field: 'average_transaction_amount',
        },
        maxTransactionAmount: {
            type: DataTypes.DECIMAL(15, 2),
            allowNull: false,
            defaultValue: 0,
            field: 'max_transaction_amount',
        },
        transactionStdDev: {
            type: DataTypes.DECIMAL(15, 2),
            allowNull: false,
            defaultValue: 0,
            field: 'transaction_std_dev',
        },
        uniqueRecipients: {
            type: DataTypes.INTEGER,
            allowNull: false,
            defaultValue: 0,
            field: 'unique_recipients',
        },
        uniqueCountries: {
            type: DataTypes.INTEGER,
            allowNull: false,
            defaultValue: 0,
            field: 'unique_countries',
        },
        uniqueDevices: {
            type: DataTypes.INTEGER,
            allowNull: false,
            defaultValue: 0,
            field: 'unique_devices',
        },
        fraudFlagCount: {
            type: DataTypes.INTEGER,
            allowNull: false,
            defaultValue: 0,
            field: 'fraud_flag_count',
        },
        lastFraudFlagAt: {
            type: DataTypes.DATE,
            allowNull: true,
            field: 'last_fraud_flag_at',
        },
        suspiciousActivityCount: {
            type: DataTypes.INTEGER,
            allowNull: false,
            defaultValue: 0,
            field: 'suspicious_activity_count',
        },
        approvedHighRiskCount: {
            type: DataTypes.INTEGER,
            allowNull: false,
            defaultValue: 0,
            field: 'approved_high_risk_count',
        },
        accountCreatedAt: {
            type: DataTypes.DATE,
            allowNull: false,
            field: 'account_created_at',
        },
        lastTransactionAt: {
            type: DataTypes.DATE,
            allowNull: true,
            field: 'last_transaction_at',
        },
        lastAnalyzedAt: {
            type: DataTypes.DATE,
            allowNull: true,
            field: 'last_analyzed_at',
        },
        preferredHours: {
            type: DataTypes.ARRAY(DataTypes.INTEGER),
            allowNull: false,
            defaultValue: [],
            field: 'preferred_hours',
        },
        preferredDays: {
            type: DataTypes.ARRAY(DataTypes.INTEGER),
            allowNull: false,
            defaultValue: [],
            field: 'preferred_days',
        },
        knownCountries: {
            type: DataTypes.ARRAY(DataTypes.STRING),
            allowNull: false,
            defaultValue: [],
            field: 'known_countries',
        },
        knownDevices: {
            type: DataTypes.ARRAY(DataTypes.STRING),
            allowNull: false,
            defaultValue: [],
            field: 'known_devices',
        },
        trustedRecipients: {
            type: DataTypes.ARRAY(DataTypes.STRING),
            allowNull: false,
            defaultValue: [],
            field: 'trusted_recipients',
        },
        isWhitelisted: {
            type: DataTypes.BOOLEAN,
            allowNull: false,
            defaultValue: false,
            field: 'is_whitelisted',
        },
        whitelistReason: {
            type: DataTypes.TEXT,
            allowNull: true,
            field: 'whitelist_reason',
        },
        whitelistExpiresAt: {
            type: DataTypes.DATE,
            allowNull: true,
            field: 'whitelist_expires_at',
        },
        isFlagged: {
            type: DataTypes.BOOLEAN,
            allowNull: false,
            defaultValue: false,
            field: 'is_flagged',
        },
        flagReason: {
            type: DataTypes.TEXT,
            allowNull: true,
            field: 'flag_reason',
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
        tableName: 'user_risk_profiles',
        indexes: [
            { fields: ['user_id'], unique: true },
            { fields: ['risk_level'] },
            { fields: ['current_risk_score'] },
            { fields: ['is_whitelisted'] },
            { fields: ['is_flagged'] },
            { fields: ['fraud_flag_count'] },
            { fields: ['last_analyzed_at'] },
        ],
    }
);
