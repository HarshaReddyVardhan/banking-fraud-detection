import { Kafka, Consumer, EachMessagePayload, ConsumerConfig, KafkaMessage } from 'kafkajs';
import { config } from '../config/config';
import { logger, fraudLogger } from '../middleware/requestLogger';
import { TransactionCreatedEvent } from '../types';

/**
 * Message handler type for transaction events
 */
export type TransactionEventHandler = (event: TransactionCreatedEvent) => Promise<void>;

/**
 * Kafka Event Consumer for incoming transaction events
 * Consumes from banking.transfers.created topic
 */
export class EventConsumer {
    private kafka: Kafka;
    private consumer: Consumer | null = null;
    private isConnected: boolean = false;
    private isRunning: boolean = false;
    private readonly serviceName = config.serviceName;
    private messageHandler: TransactionEventHandler | null = null;

    constructor() {
        this.kafka = new Kafka({
            clientId: config.kafka.clientId,
            brokers: config.kafka.brokers,
            connectionTimeout: config.kafka.connectionTimeout,
            retry: {
                initialRetryTime: 100,
                retries: 10,
                maxRetryTime: 30000,
                multiplier: 2,
            },
        });
    }

    /**
     * Set the message handler for transaction events
     */
    setHandler(handler: TransactionEventHandler): void {
        this.messageHandler = handler;
    }

    /**
     * Connect and start consuming
     */
    async connect(): Promise<void> {
        if (this.isConnected) return;

        try {
            const consumerConfig: ConsumerConfig = {
                groupId: config.kafka.groupId,
                sessionTimeout: config.kafka.sessionTimeout,
                heartbeatInterval: 3000,
                maxBytesPerPartition: 1048576, // 1MB
                maxWaitTimeInMs: 5000,
            };

            this.consumer = this.kafka.consumer(consumerConfig);

            // Event listeners for monitoring
            this.consumer.on('consumer.connect', () => {
                logger.info('Kafka consumer connected', { groupId: config.kafka.groupId });
            });

            this.consumer.on('consumer.disconnect', () => {
                logger.warn('Kafka consumer disconnected');
                this.isConnected = false;
            });

            this.consumer.on('consumer.crash', (event) => {
                logger.error('Kafka consumer crashed', { error: event.payload.error });
                this.isConnected = false;
            });

            this.consumer.on('consumer.rebalancing', () => {
                logger.info('Kafka consumer rebalancing');
            });

            await this.consumer.connect();
            this.isConnected = true;
            logger.info('Kafka consumer connected successfully');
        } catch (error) {
            logger.error('Failed to connect Kafka consumer', { error });
            throw error;
        }
    }

    /**
     * Subscribe to topics and start consuming
     */
    async start(): Promise<void> {
        if (!this.consumer || !this.isConnected) {
            throw new Error('Consumer not connected. Call connect() first.');
        }

        if (!this.messageHandler) {
            throw new Error('Message handler not set. Call setHandler() first.');
        }

        if (this.isRunning) {
            logger.warn('Consumer already running');
            return;
        }

        try {
            // Subscribe to transaction created topic
            await this.consumer.subscribe({
                topic: config.kafka.topics.transactionCreated,
                fromBeginning: false,
            });

            logger.info('Subscribed to topics', {
                topic: config.kafka.topics.transactionCreated,
                groupId: config.kafka.groupId,
            });

            // Start consuming
            await this.consumer.run({
                autoCommit: true,
                autoCommitInterval: 5000,
                autoCommitThreshold: 100,
                eachMessage: async (payload: EachMessagePayload) => {
                    await this.handleMessage(payload);
                },
            });

            this.isRunning = true;
            logger.info('Kafka consumer started running');
        } catch (error) {
            logger.error('Failed to start Kafka consumer', { error });
            throw error;
        }
    }

    /**
     * Handle incoming message
     */
    private async handleMessage(payload: EachMessagePayload): Promise<void> {
        const { topic, partition, message } = payload;
        const startTime = Date.now();

        try {
            const event = this.parseMessage(message);

            if (!event) {
                logger.warn('Failed to parse message', {
                    topic,
                    partition,
                    offset: message.offset,
                });
                return;
            }

            // Validate event
            if (!this.validateEvent(event)) {
                logger.warn('Invalid event structure', {
                    topic,
                    partition,
                    offset: message.offset,
                    transactionId: event.payload?.transactionId,
                });
                return;
            }

            fraudLogger.analysisStarted(
                event.payload.transactionId,
                event.payload.userId,
                event.correlationId
            );

            // Process the event
            if (this.messageHandler) {
                await this.messageHandler(event);
            }

            logger.debug('Message processed', {
                topic,
                partition,
                offset: message.offset,
                transactionId: event.payload.transactionId,
                processingTimeMs: Date.now() - startTime,
            });
        } catch (error) {
            logger.error('Error processing message', {
                topic,
                partition,
                offset: message.offset,
                error,
                processingTimeMs: Date.now() - startTime,
            });
            // Throw to trigger KafkaJS retry (exponential backoff)
            throw error;
        }
    }

    /**
     * Parse Kafka message to TransactionCreatedEvent
     */
    private parseMessage(message: KafkaMessage): TransactionCreatedEvent | null {
        try {
            if (!message.value) {
                return null;
            }

            const rawValue = message.value.toString();
            const event = JSON.parse(rawValue) as TransactionCreatedEvent;
            return event;
        } catch (error) {
            logger.error('Failed to parse message', { error });
            return null;
        }
    }

    /**
     * Validate event structure
     */
    private validateEvent(event: TransactionCreatedEvent): boolean {
        if (!event || !event.payload) {
            return false;
        }

        const { payload } = event;

        // Required fields validation
        if (!payload.transactionId || typeof payload.transactionId !== 'string') {
            return false;
        }

        if (!payload.userId || typeof payload.userId !== 'string') {
            return false;
        }

        if (typeof payload.amount !== 'number' || payload.amount <= 0) {
            return false;
        }

        if (!payload.recipientId || typeof payload.recipientId !== 'string') {
            return false;
        }

        return true;
    }

    /**
     * Disconnect the consumer
     */
    async disconnect(): Promise<void> {
        if (this.consumer && this.isConnected) {
            await this.consumer.disconnect();
            this.isConnected = false;
            this.isRunning = false;
            logger.info('Kafka consumer disconnected');
        }
    }

    /**
     * Check if consumer is connected
     */
    isConsumerConnected(): boolean {
        return this.isConnected;
    }

    /**
     * Check if consumer is running
     */
    isConsumerRunning(): boolean {
        return this.isRunning;
    }

    /**
     * Pause consumption (for graceful shutdown)
     */
    async pause(): Promise<void> {
        if (this.consumer && this.isRunning) {
            this.consumer.pause([{ topic: config.kafka.topics.transactionCreated }]);
            logger.info('Kafka consumer paused');
        }
    }

    /**
     * Resume consumption
     */
    async resume(): Promise<void> {
        if (this.consumer && this.isRunning) {
            this.consumer.resume([{ topic: config.kafka.topics.transactionCreated }]);
            logger.info('Kafka consumer resumed');
        }
    }
}

// Export singleton
export const eventConsumer = new EventConsumer();
