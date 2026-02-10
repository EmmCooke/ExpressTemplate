# middleware/

Express middleware functions:

- **authenticate.ts** — JWT token verification.
- **authorize.ts** — Role-based access control.
- **errorHandler.ts** — Centralized error handler (must be last).
- **notFound.ts** — 404 catch-all (after all routes).
- **rateLimiter.ts** — Rate limiting configuration.
- **requestLogger.ts** — HTTP request logging.
- **validate.ts** — Zod schema validation.
