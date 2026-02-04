import { Router, Request, Response } from 'express';
import { cacheService } from '../services/CacheService';
import { eventConsumer } from '../kafka/EventConsumer';
import { config } from '../config/config';

const router = Router();

router.get('/health', async (_req: Request, res: Response) => {
    const redisConnected = cacheService.isRedisConnected();
    const kafkaConnected = eventConsumer.isConsumerConnected();

    // Check DB status if possible (not exposed directly, maybe add method later)
    // For now assuming DB failure would be caught by global error handler or initial connection check

    const status = (redisConnected && kafkaConnected) ? 'healthy' : 'degraded';

    res.status(200).json({
        status,
        service: config.serviceName,
        timestamp: new Date().toISOString(),
        checks: {
            redis: redisConnected ? 'up' : 'down',
            kafka: kafkaConnected ? 'up' : 'down'
        }
    });
});

export default router;
