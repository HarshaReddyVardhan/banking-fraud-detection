import app from './app';
import { config } from './config/config';
import { logger } from './middleware/requestLogger';
import { initializeDatabase, closeDatabase } from './models';
import { cacheService } from './services/CacheService';
import { eventConsumer } from './kafka/EventConsumer';
import { eventPublisher } from './kafka/EventPublisher';
import { fraudDetectionService } from './services/FraudDetectionService';
import { mlModelService } from './services/MLModelService';

async function startServer() {
    try {
        logger.info(`Starting ${config.serviceName}...`);

        // 1. Initialize Database
        await initializeDatabase();

        // 2. Initialize Redis
        await cacheService.connect();

        // 3. Initialize ML Model
        await mlModelService.loadModel();

        // 4. Initialize Kafka Producer
        await eventPublisher.connect();

        // 5. Initialize Kafka Consumer & Set Handler
        eventConsumer.setHandler(async (event) => {
            await fraudDetectionService.processTransaction(event);
        });
        await eventConsumer.connect();
        await eventConsumer.start();

        // 6. Start Express Server
        app.listen(config.port, config.host, () => {
            logger.info(`Server running on http://${config.host}:${config.port}`);
            logger.info(`Environment: ${config.nodeEnv}`);
        });

    } catch (error) {
        logger.error('Failed to start server', { error });
        process.exit(1);
    }
}

startServer();

// Handle graceful shutdown
const shutdown = async () => {
    logger.info('Shutting down service...');
    try {
        await eventConsumer.disconnect();
        await eventPublisher.disconnect();
        await cacheService.disconnect();
        await closeDatabase();
        logger.info('Service shutdown complete');
        process.exit(0);
    } catch (error) {
        logger.error('Error during shutdown', { error });
        process.exit(1);
    }
};

process.on('SIGTERM', shutdown);
process.on('SIGINT', shutdown);
