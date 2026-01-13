import { AmountAnalyzer } from '../../src/services/AmountAnalyzer';
import { UserTransactionHistory } from '../../src/types';

// Mock logger
jest.mock('../../src/middleware/requestLogger', () => ({
    logger: {
        debug: jest.fn(),
        error: jest.fn(),
        info: jest.fn(),
    }
}));

// Mock config
jest.mock('../../src/config/config', () => ({
    config: {
        analysis: {
            amount: {
                unusualMultiplier: 5.0,
                largeTransferMin: 10000,
            }
        },
        thresholds: {
            amountWeight: 0.25
        }
    }
}));

describe('AmountAnalyzer', () => {
    let analyzer: AmountAnalyzer;
    const mockUserId = 'user-123';
    const mockTxId = 'tx-123';

    beforeEach(() => {
        analyzer = new AmountAnalyzer();
    });

    it('should detect unusually large amount compared to average', async () => {
        const history: UserTransactionHistory = {
            userId: mockUserId,
            transactions: [],
            statistics: {
                totalTransactions: 10,
                averageAmount: 100,
                maxAmount: 200,
                minAmount: 10,
                standardDeviation: 20,
                uniqueRecipients: 10,
                uniqueCountries: 1,
                uniqueDevices: 1,
                accountCreatedAt: new Date().toISOString()
            },
            cachedAt: new Date().toISOString()
        };

        const result = await analyzer.analyze(mockUserId, mockTxId, 600, 'USD', history);

        expect(result.score).toBeGreaterThan(0);
        expect(result.reason).toContain('higher than user average');
    });

    it('should detect amount exceeding historical max', async () => {
        const history: UserTransactionHistory = {
            userId: mockUserId,
            transactions: [],
            statistics: {
                totalTransactions: 10,
                averageAmount: 100,
                maxAmount: 200,
                minAmount: 10,
                standardDeviation: 20,
                uniqueRecipients: 1,
                uniqueCountries: 1,
                uniqueDevices: 1,
                accountCreatedAt: new Date().toISOString()
            },
            cachedAt: new Date().toISOString()
        };

        const result = await analyzer.analyze(mockUserId, mockTxId, 500, 'USD', history);

        expect(result.score).toBeGreaterThan(0);
        expect(result.reason).toContain('exceeds 2x user\'s historical max');
    });

    it('should return normal for typical amount', async () => {
        const history: UserTransactionHistory = {
            userId: mockUserId,
            transactions: [],
            statistics: {
                totalTransactions: 10,
                averageAmount: 100,
                maxAmount: 200,
                minAmount: 10,
                standardDeviation: 20,
                uniqueRecipients: 1,
                uniqueCountries: 1,
                uniqueDevices: 1,
                accountCreatedAt: new Date().toISOString()
            },
            cachedAt: new Date().toISOString()
        };

        const result = await analyzer.analyze(mockUserId, mockTxId, 110, 'USD', history);

        expect(result.score).toBe(0);
        expect(result.reason).toBe('Normal transaction amount');
    });

    it('should detect round numbers', async () => {
        const result = await analyzer.analyze(mockUserId, mockTxId, 10000, 'USD', null);
        expect(result.score).toBeGreaterThan(0);
        expect(result.reason).toContain('Perfectly round amount');
    });
});
