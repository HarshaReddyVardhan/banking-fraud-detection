import { Kafka, Producer, Partitioners, CompressionTypes, RecordMetadata } from 'kafkajs';
import { v4 as uuidv4 } from 'uuid';
import { config } from '../config/config';
import { logger, fraudLogger } from '../middleware/requestLogger';
import { FraudAnalysisResult, FraudAnalysisEvent, ManualReviewRequest } from '../types';

/**
 * Fraud event types for publishing
 */
export type FraudEventType =
    | 'FraudAnalysisComplete'
    | 'FraudSuspected'
    | 'FraudRejected'
    | 'ManualReviewRequired'
    | 'ManualReviewComplete'
    | 'BlocklistMatch';

/**
 * Kafka Event Publisher for fraud detection results
 */
export class EventPublisher {
    private kafka: Kafka;
    private producer: Producer | null = null;
    private isConnected: boolean = false;
    private readonly serviceName = config.serviceName;
    private readonly eventVersion = '1.0';

    constructor() {
        this.kafka = new Kafka({
            clientId: config.kafka.clientId,
            brokers: config.kafka.brokers,
            connectionTimeout: config.kafka.connectionTimeout,
            retry: {
                initialRetryTime: 100,
                retries: 5,
            },
        });
    }

    /**
     * Initialize and connect the producer
     */
    async connect(): Promise<void> {
        if (this.isConnected) return;

        try {
            this.producer = this.kafka.producer({
                createPartitioner: Partitioners.DefaultPartitioner,
                allowAutoTopicCreation: true,
                transactionTimeout: 30000,
                idempotent: true, // Exactly-once semantics
            });

            await this.producer.connect();
            this.isConnected = true;
            logger.info('Kafka producer connected');
        } catch (error) {
            logger.error('Failed to connect Kafka producer', { error });
            // Don't throw - allow service to run without Kafka
        }
    }

    /**
     * Disconnect the producer
     */
    async disconnect(): Promise<void> {
        if (this.producer && this.isConnected) {
            await this.producer.disconnect();
            this.isConnected = false;
            logger.info('Kafka producer disconnected');
        }
    }

    /**
     * Publish fraud analysis complete event
     */
    async publishAnalysisComplete(
        result: FraudAnalysisResult,
        correlationId?: string
    ): Promise<void> {
        const event: FraudAnalysisEvent = {
            eventType: 'FraudAnalysisComplete',
            eventId: uuidv4(),
            timestamp: new Date().toISOString(),
            version: this.eventVersion,
            service: this.serviceName,
            correlationId,
            payload: result,
        };

        await this.publish(config.kafka.topics.fraudAnalysis, event, result.transactionId);

        logger.info('Published fraud analysis complete event', {
            transactionId: result.transactionId,
            decision: result.decision,
            score: result.score,
        });
    }

    /**
     * Publish fraud suspected event (high-risk detection)
     */
    async publishFraudSuspected(
        result: FraudAnalysisResult,
        correlationId?: string
    ): Promise<void> {
        const event: FraudAnalysisEvent = {
            eventType: 'FraudSuspected',
            eventId: uuidv4(),
            timestamp: new Date().toISOString(),
            version: this.eventVersion,
            service: this.serviceName,
            correlationId,
            payload: result,
        };

        await this.publish(config.kafka.topics.fraudSuspected, event, result.transactionId);

        fraudLogger.fraudDetected(
            result.transactionId,
            result.userId,
            result.score,
            result.riskFactors.map(rf => rf.reason),
            correlationId
        );
    }

    /**
     * Publish manual review required event
     */
    async publishManualReviewRequired(
        reviewRequest: ManualReviewRequest,
        correlationId?: string
    ): Promise<void> {
        const event = {
            eventType: 'ManualReviewRequired' as const,
            eventId: uuidv4(),
            timestamp: new Date().toISOString(),
            version: this.eventVersion,
            service: this.serviceName,
            correlationId,
            payload: reviewRequest,
        };

        await this.publish(config.kafka.topics.fraudManualReview, event, reviewRequest.transactionId);

        fraudLogger.manualReviewCreated(
            reviewRequest.analysisId,
            reviewRequest.transactionId,
            reviewRequest.priority
        );
    }

    /**
     * Publish manual review complete event
     */
    async publishManualReviewComplete(
        transactionId: string,
        analysisId: string,
        reviewerId: string,
        decision: 'APPROVED' | 'REJECTED' | 'ESCALATED' | 'INFO_REQUESTED',
        reason: string,
        correlationId?: string
    ): Promise<void> {
        const event = {
            eventType: 'ManualReviewComplete' as const,
            eventId: uuidv4(),
            timestamp: new Date().toISOString(),
            version: this.eventVersion,
            service: this.serviceName,
            correlationId,
            payload: {
                transactionId,
                analysisId,
                reviewerId,
                decision,
                reason,
            },
        };

        await this.publish(config.kafka.topics.fraudReviewComplete, event, transactionId);

        fraudLogger.manualReviewCompleted(
            analysisId,
            transactionId,
            reviewerId,
            decision
        );
    }

    /**
     * Publish blocklist match event
     */
    async publishBlocklistMatch(
        transactionId: string,
        userId: string,
        blocklistType: string,
        blocklistId: string,
        reason: string,
        correlationId?: string
    ): Promise<void> {
        const event = {
            eventType: 'BlocklistMatch' as const,
            eventId: uuidv4(),
            timestamp: new Date().toISOString(),
            version: this.eventVersion,
            service: this.serviceName,
            correlationId,
            payload: {
                transactionId,
                userId,
                blocklistType,
                blocklistId,
                reason,
                decision: 'REJECT',
                score: 1.0,
            },
        };

        await this.publish(config.kafka.topics.fraudSuspected, event, transactionId);

        fraudLogger.blocklistMatch(blocklistType, blocklistId, transactionId);
    }

    /**
     * Internal publish method
     */
    private async publish(
        topic: string,
        event: any,
        key: string
    ): Promise<RecordMetadata[] | null> {
        if (!this.producer || !this.isConnected) {
            // Log event locally if Kafka not available
            logger.info('Fraud event (Kafka offline)', {
                topic,
                eventType: event['eventType'],
                transactionId: key,
            });
            return null;
        }

        try {
            const result = await this.producer.send({
                topic,
                compression: CompressionTypes.GZIP,
                messages: [
                    {
                        key,
                        value: JSON.stringify(event),
                        headers: {
                            'event-type': String(event['eventType']),
                            'event-version': this.eventVersion,
                            'source-service': this.serviceName,
                            'correlation-id': String(event['correlationId'] ?? ''),
                        },
                    },
                ],
            });

            logger.debug('Event published to Kafka', {
                topic,
                eventType: event['eventType'],
                key,
                partition: result[0]?.partition,
                offset: result[0]?.offset,
            });

            return result;
        } catch (error) {
            logger.error('Failed to publish event to Kafka', {
                topic,
                eventType: event['eventType'],
                key,
                error,
            });
            // Don't throw - log error and continue
            return null;
        }
    }

    /**
     * Check if producer is connected
     */
    isProducerConnected(): boolean {
        return this.isConnected;
    }
}

// Export singleton
export const eventPublisher = new EventPublisher();
