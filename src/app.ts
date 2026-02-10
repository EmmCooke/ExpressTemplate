import express from "express";
import helmet from "helmet";
import cors from "cors";
import compression from "compression";
import { pinoHttp } from "pino-http";
import { rateLimiter } from "./middleware/rateLimiter.js";
import { routes } from "./routes/index.js";
import { notFoundHandler } from "./middleware/notFound.js";
import { errorHandler } from "./middleware/errorHandler.js";
import { env } from "./config/env.js";

const app = express();

// 1. Security headers
app.use(helmet());

// 2. CORS
app.use(cors({ origin: env.CORS_ORIGIN, credentials: true }));

// 3. Compression
app.use(compression());

// 4. Body parsing
app.use(express.json({ limit: "10kb" }));
app.use(express.urlencoded({ extended: true, limit: "10kb" }));

// 5. Request logging
app.use(pinoHttp());

// 6. Rate limiting
app.use(rateLimiter);

// 7. Application routes
app.use("/api", routes);

// 8. 404 handler (after all routes)
app.use(notFoundHandler);

// 9. Centralized error handler (always last)
app.use(errorHandler);

export { app };
