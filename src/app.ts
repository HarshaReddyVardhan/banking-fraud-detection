import express from 'express';
import helmet from 'helmet';
import cors from 'cors';
import compression from 'compression';
import { rateLimit } from 'express-rate-limit'; // check syntax
import { errorHandler, notFoundHandler } from './middleware/errorHandler';
import { requestLoggerMiddleware } from './middleware/requestLogger';
import routes from './routes';
import { config } from './config/config';

const app = express();

// Security Middleware
app.use(helmet());
app.use(cors());
app.use(compression());

// Rate Limiting
// 100 requests per 15 minutes by default
const limiter = rateLimit({
    windowMs: 15 * 60 * 1000,
    limit: 100,
    standardHeaders: 'draft-7',
    legacyHeaders: false,
    message: {
        success: false,
        error: {
            code: 'RATE_LIMIT_EXCEEDED',
            message: 'Too many requests, please try again later.'
        }
    }
});
app.use(limiter);

// Body parsing with size limit from config
app.use(express.json({ limit: config.security.maxRequestSize }));

// Request Logging
app.use(requestLoggerMiddleware);

// Routes
app.use('/api/v1', routes);

// 404 & Error Handling
app.use(notFoundHandler);
app.use(errorHandler);

export default app;
