# CLAUDE.md - Express.js Codebase Guide for AI Assistants

## Project Overview

This is a **backend API** built with **Express 5** and **TypeScript**, running on **Node.js**. It follows a layered architecture with clear separation of concerns: routes define endpoints, controllers handle HTTP concerns, services contain business logic, and repositories manage data access. Validation is handled with **Zod**, and the database layer uses **Prisma** (or **Drizzle** as an alternative). Authentication relies on **JWT** with optional **Passport.js** strategies.

### Tech Stack

| Layer              | Technology                        |
| ------------------ | --------------------------------- |
| Runtime            | Node.js 20+                       |
| Framework          | Express 5                          |
| Language           | TypeScript 5+                      |
| ORM / Query Builder| Prisma or Drizzle                  |
| Validation         | Zod                                |
| Authentication     | JWT (jsonwebtoken), Passport.js    |
| Testing            | Vitest (or Jest) + Supertest       |
| Logging            | Pino (or Winston) + Morgan         |
| Security           | Helmet, CORS, express-rate-limit   |
| Process Manager    | PM2 (production)                   |
| Containerization   | Docker + docker-compose            |

---

## Project Structure

```
src/
├── config/
│   ├── database.ts          # Database connection and configuration
│   ├── env.ts               # Environment variable validation (Zod)
│   ├── logger.ts            # Logger instance configuration
│   └── passport.ts          # Passport.js strategy definitions
├── controllers/
│   ├── auth.controller.ts   # Authentication endpoints
│   ├── user.controller.ts   # User CRUD endpoints
│   └── post.controller.ts   # Post CRUD endpoints
├── middleware/
│   ├── authenticate.ts      # JWT / session verification
│   ├── authorize.ts         # Role-based access control
│   ├── errorHandler.ts      # Centralized error handler
│   ├── notFound.ts          # 404 catch-all handler
│   ├── rateLimiter.ts       # Rate limiting configuration
│   ├── requestLogger.ts     # HTTP request logging (Morgan/Pino)
│   └── validate.ts          # Zod schema validation middleware
├── models/
│   ├── prisma/
│   │   └── schema.prisma    # Prisma schema definition
│   └── drizzle/
│       ├── schema.ts        # Drizzle table definitions
│       └── migrations/      # SQL migration files
├── repositories/
│   ├── user.repository.ts   # User data access layer
│   └── post.repository.ts   # Post data access layer
├── routes/
│   ├── index.ts             # Root router, mounts all sub-routers
│   ├── v1/
│   │   ├── index.ts         # v1 router aggregator
│   │   ├── auth.routes.ts   # /api/v1/auth/*
│   │   ├── user.routes.ts   # /api/v1/users/*
│   │   └── post.routes.ts   # /api/v1/posts/*
│   └── v2/
│       └── index.ts         # v2 router aggregator (future)
├── services/
│   ├── auth.service.ts      # Authentication business logic
│   ├── user.service.ts      # User business logic
│   ├── post.service.ts      # Post business logic
│   └── email.service.ts     # Email sending logic
├── types/
│   ├── express.d.ts         # Express type augmentations
│   ├── environment.d.ts     # process.env type declarations
│   └── common.ts            # Shared type definitions
├── utils/
│   ├── asyncHandler.ts      # Async route wrapper
│   ├── ApiError.ts          # Custom error class
│   ├── ApiResponse.ts       # Standardized response helper
│   └── pagination.ts        # Pagination utility
├── validators/
│   ├── auth.validator.ts    # Auth request schemas (Zod)
│   ├── user.validator.ts    # User request schemas (Zod)
│   ├── post.validator.ts    # Post request schemas (Zod)
│   └── common.validator.ts  # Shared schemas (pagination, ID params)
├── app.ts                   # Express app setup (middleware, routes)
└── server.ts                # HTTP server bootstrap (listen)
prisma/
├── schema.prisma            # Prisma schema (if at root)
└── migrations/              # Prisma migration history
tests/
├── integration/
│   ├── auth.test.ts
│   ├── user.test.ts
│   └── post.test.ts
├── unit/
│   ├── services/
│   │   └── user.service.test.ts
│   └── utils/
│       └── pagination.test.ts
├── helpers/
│   ├── setup.ts             # Global test setup
│   └── factories.ts         # Test data factories
└── vitest.config.ts         # Test runner configuration
docker/
├── Dockerfile
├── Dockerfile.dev
└── docker-compose.yml
.env.example
tsconfig.json
package.json
```

---

## Naming Conventions

### File Naming

| Type        | Convention               | Example                   |
| ----------- | ------------------------ | ------------------------- |
| Routes      | `<resource>.routes.ts`   | `user.routes.ts`          |
| Controllers | `<resource>.controller.ts` | `user.controller.ts`    |
| Services    | `<resource>.service.ts`  | `user.service.ts`         |
| Repositories| `<resource>.repository.ts` | `user.repository.ts`   |
| Middleware  | `camelCase.ts`           | `authenticate.ts`         |
| Validators  | `<resource>.validator.ts`| `user.validator.ts`       |
| Types       | `camelCase.ts` or `<resource>.d.ts` | `express.d.ts` |
| Tests       | `<resource>.<layer>.test.ts` | `user.service.test.ts` |
| Config      | `camelCase.ts`           | `database.ts`             |

### Code Naming

| Element       | Convention      | Example                          |
| ------------- | --------------- | -------------------------------- |
| Variables     | camelCase       | `const userName = ...`           |
| Functions     | camelCase       | `function getUsers() {}`         |
| Classes       | PascalCase      | `class ApiError extends Error {}`|
| Interfaces    | PascalCase      | `interface UserPayload {}`       |
| Type aliases  | PascalCase      | `type PaginatedResult<T> = ...`  |
| Enums         | PascalCase      | `enum Role { Admin, User }`      |
| Constants     | UPPER_SNAKE_CASE| `const MAX_RETRIES = 3`          |
| Env variables | UPPER_SNAKE_CASE| `DATABASE_URL`                   |
| Route paths   | kebab-case      | `/api/v1/user-profiles`          |
| DB columns    | snake_case      | `created_at`, `first_name`       |

### Route Naming (RESTful)

| Action     | Method   | Path                    | Controller Method |
| ---------- | -------- | ----------------------- | ----------------- |
| List all   | `GET`    | `/api/v1/users`         | `getUsers`        |
| Get one    | `GET`    | `/api/v1/users/:id`     | `getUserById`     |
| Create     | `POST`   | `/api/v1/users`         | `createUser`      |
| Update     | `PUT`    | `/api/v1/users/:id`     | `updateUser`      |
| Partial    | `PATCH`  | `/api/v1/users/:id`     | `patchUser`       |
| Delete     | `DELETE` | `/api/v1/users/:id`     | `deleteUser`      |
| Nested     | `GET`    | `/api/v1/users/:id/posts` | `getUserPosts`  |

---

## Middleware Patterns

### Middleware Application Order in `app.ts`

The order in which middleware is registered matters. Follow this sequence:

```typescript
// app.ts
import express from "express";
import helmet from "helmet";
import cors from "cors";
import compression from "compression";
import { pinoHttp } from "pino-http";
import { rateLimiter } from "./middleware/rateLimiter";
import { routes } from "./routes";
import { notFoundHandler } from "./middleware/notFound";
import { errorHandler } from "./middleware/errorHandler";
import { env } from "./config/env";

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
```

### Custom Middleware Pattern

```typescript
// middleware/authenticate.ts
import { Request, Response, NextFunction } from "express";
import jwt from "jsonwebtoken";
import { env } from "../config/env";
import { ApiError } from "../utils/ApiError";

export function authenticate(req: Request, _res: Response, next: NextFunction): void {
  const header = req.headers.authorization;
  if (!header?.startsWith("Bearer ")) {
    throw new ApiError(401, "Missing or invalid Authorization header");
  }

  const token = header.split(" ")[1];
  try {
    const payload = jwt.verify(token, env.JWT_SECRET) as { userId: string; role: string };
    req.user = payload;
    next();
  } catch {
    throw new ApiError(401, "Invalid or expired token");
  }
}
```

### Error-Handling Middleware

Error-handling middleware in Express has **four** parameters. It must be the last `app.use()` call:

```typescript
// middleware/errorHandler.ts
import { Request, Response, NextFunction } from "express";
import { ZodError } from "zod";
import { ApiError } from "../utils/ApiError";
import { logger } from "../config/logger";

export function errorHandler(
  err: Error,
  _req: Request,
  res: Response,
  _next: NextFunction
): void {
  // Zod validation errors
  if (err instanceof ZodError) {
    res.status(400).json({
      success: false,
      message: "Validation failed",
      errors: err.errors.map((e) => ({
        path: e.path.join("."),
        message: e.message,
      })),
    });
    return;
  }

  // Custom API errors
  if (err instanceof ApiError) {
    res.status(err.statusCode).json({
      success: false,
      message: err.message,
      ...(err.errors && { errors: err.errors }),
    });
    return;
  }

  // Unexpected errors
  logger.error(err, "Unhandled error");
  res.status(500).json({
    success: false,
    message: "Internal Server Error",
  });
}
```

---

## Routing Best Practices

### Router Organization

```typescript
// routes/v1/user.routes.ts
import { Router } from "express";
import { UserController } from "../../controllers/user.controller";
import { authenticate } from "../../middleware/authenticate";
import { authorize } from "../../middleware/authorize";
import { validate } from "../../middleware/validate";
import { createUserSchema, updateUserSchema } from "../../validators/user.validator";
import { paginationSchema } from "../../validators/common.validator";

const router = Router();
const controller = new UserController();

router.get("/", authenticate, validate({ query: paginationSchema }), controller.getUsers);
router.get("/:id", authenticate, controller.getUserById);
router.post("/", authenticate, authorize("admin"), validate({ body: createUserSchema }), controller.createUser);
router.put("/:id", authenticate, authorize("admin"), validate({ body: updateUserSchema }), controller.updateUser);
router.delete("/:id", authenticate, authorize("admin"), controller.deleteUser);

export { router as userRoutes };
```

### Versioned API Mounting

```typescript
// routes/v1/index.ts
import { Router } from "express";
import { authRoutes } from "./auth.routes";
import { userRoutes } from "./user.routes";
import { postRoutes } from "./post.routes";

const router = Router();

router.use("/auth", authRoutes);
router.use("/users", userRoutes);
router.use("/posts", postRoutes);

export { router as v1Routes };

// routes/index.ts
import { Router } from "express";
import { v1Routes } from "./v1";

const router = Router();

router.use("/v1", v1Routes);
// router.use("/v2", v2Routes);  // future

export { router as routes };
```

---

## Controller Patterns

Controllers must be **thin**. They parse the request, call services, and send responses. No business logic belongs here.

```typescript
// controllers/user.controller.ts
import { Request, Response } from "express";
import { UserService } from "../services/user.service";
import { asyncHandler } from "../utils/asyncHandler";

const userService = new UserService();

export class UserController {
  getUsers = asyncHandler(async (req: Request, res: Response) => {
    const { page, limit } = req.query as { page?: string; limit?: string };
    const result = await userService.findAll({
      page: Number(page) || 1,
      limit: Number(limit) || 20,
    });
    res.json({ success: true, data: result });
  });

  getUserById = asyncHandler(async (req: Request, res: Response) => {
    const user = await userService.findById(req.params.id);
    res.json({ success: true, data: user });
  });

  createUser = asyncHandler(async (req: Request, res: Response) => {
    const user = await userService.create(req.body);
    res.status(201).json({ success: true, data: user });
  });

  updateUser = asyncHandler(async (req: Request, res: Response) => {
    const user = await userService.update(req.params.id, req.body);
    res.json({ success: true, data: user });
  });

  deleteUser = asyncHandler(async (req: Request, res: Response) => {
    await userService.delete(req.params.id);
    res.status(204).send();
  });
}
```

---

## Error Handling

### Custom Error Class

```typescript
// utils/ApiError.ts
export class ApiError extends Error {
  public readonly statusCode: number;
  public readonly isOperational: boolean;
  public readonly errors?: Record<string, string>[];

  constructor(
    statusCode: number,
    message: string,
    errors?: Record<string, string>[],
    isOperational = true
  ) {
    super(message);
    this.statusCode = statusCode;
    this.isOperational = isOperational;
    this.errors = errors;
    Object.setPrototypeOf(this, ApiError.prototype);
    Error.captureStackTrace(this, this.constructor);
  }

  static badRequest(message = "Bad Request") {
    return new ApiError(400, message);
  }

  static unauthorized(message = "Unauthorized") {
    return new ApiError(401, message);
  }

  static forbidden(message = "Forbidden") {
    return new ApiError(403, message);
  }

  static notFound(message = "Resource not found") {
    return new ApiError(404, message);
  }

  static conflict(message = "Conflict") {
    return new ApiError(409, message);
  }

  static internal(message = "Internal Server Error") {
    return new ApiError(500, message, undefined, false);
  }
}
```

### Async Handler Wrapper

Express 5 natively catches rejected promises from async handlers. However, if using Express 4 or wanting explicit control, use a wrapper:

```typescript
// utils/asyncHandler.ts
import { Request, Response, NextFunction, RequestHandler } from "express";

export function asyncHandler(
  fn: (req: Request, res: Response, next: NextFunction) => Promise<void>
): RequestHandler {
  return (req, res, next) => {
    Promise.resolve(fn(req, res, next)).catch(next);
  };
}
```

> **Express 5 Note:** Express 5 automatically forwards rejected promises to `next()`, so `asyncHandler` is optional if you are on Express 5. It remains useful for explicit error transforms.

---

## Validation with Zod

### Schema Definitions

```typescript
// validators/user.validator.ts
import { z } from "zod";

export const createUserSchema = z.object({
  email: z.string().email("Invalid email address"),
  password: z
    .string()
    .min(8, "Password must be at least 8 characters")
    .regex(/[A-Z]/, "Password must contain an uppercase letter")
    .regex(/[0-9]/, "Password must contain a number"),
  name: z.string().min(1, "Name is required").max(100),
  role: z.enum(["user", "admin"]).default("user"),
});

export const updateUserSchema = createUserSchema.partial().omit({ password: true });

export type CreateUserInput = z.infer<typeof createUserSchema>;
export type UpdateUserInput = z.infer<typeof updateUserSchema>;
```

### Validation Middleware

```typescript
// middleware/validate.ts
import { Request, Response, NextFunction } from "express";
import { ZodSchema, ZodError } from "zod";

interface ValidationSchemas {
  body?: ZodSchema;
  query?: ZodSchema;
  params?: ZodSchema;
}

export function validate(schemas: ValidationSchemas) {
  return (req: Request, _res: Response, next: NextFunction): void => {
    try {
      if (schemas.body) req.body = schemas.body.parse(req.body);
      if (schemas.query) req.query = schemas.query.parse(req.query) as any;
      if (schemas.params) req.params = schemas.params.parse(req.params) as any;
      next();
    } catch (err) {
      if (err instanceof ZodError) {
        next(err); // Caught by errorHandler
      } else {
        next(err);
      }
    }
  };
}
```

---

## Authentication Patterns

### JWT Authentication

```typescript
// services/auth.service.ts
import jwt from "jsonwebtoken";
import bcrypt from "bcryptjs";
import { env } from "../config/env";
import { UserRepository } from "../repositories/user.repository";
import { ApiError } from "../utils/ApiError";

const userRepo = new UserRepository();

export class AuthService {
  async login(email: string, password: string) {
    const user = await userRepo.findByEmail(email);
    if (!user || !(await bcrypt.compare(password, user.password))) {
      throw ApiError.unauthorized("Invalid email or password");
    }

    const accessToken = jwt.sign(
      { userId: user.id, role: user.role },
      env.JWT_SECRET,
      { expiresIn: env.JWT_EXPIRES_IN }
    );

    const refreshToken = jwt.sign(
      { userId: user.id },
      env.JWT_REFRESH_SECRET,
      { expiresIn: "7d" }
    );

    return { accessToken, refreshToken, user: { id: user.id, email: user.email, role: user.role } };
  }

  async register(data: { email: string; password: string; name: string }) {
    const existing = await userRepo.findByEmail(data.email);
    if (existing) throw ApiError.conflict("Email already registered");

    const hashedPassword = await bcrypt.hash(data.password, 12);
    const user = await userRepo.create({ ...data, password: hashedPassword });
    return { id: user.id, email: user.email, name: user.name };
  }
}
```

### Role-Based Authorization Middleware

```typescript
// middleware/authorize.ts
import { Request, Response, NextFunction } from "express";
import { ApiError } from "../utils/ApiError";

export function authorize(...allowedRoles: string[]) {
  return (req: Request, _res: Response, next: NextFunction): void => {
    if (!req.user) {
      throw ApiError.unauthorized("Authentication required");
    }
    if (!allowedRoles.includes(req.user.role)) {
      throw ApiError.forbidden("Insufficient permissions");
    }
    next();
  };
}
```

---

## Database Patterns

### Prisma Repository

```typescript
// repositories/user.repository.ts
import { PrismaClient, User } from "@prisma/client";
import { ApiError } from "../utils/ApiError";

const prisma = new PrismaClient();

export class UserRepository {
  async findAll(params: { page: number; limit: number }) {
    const skip = (params.page - 1) * params.limit;
    const [users, total] = await Promise.all([
      prisma.user.findMany({
        skip,
        take: params.limit,
        select: { id: true, email: true, name: true, role: true, createdAt: true },
        orderBy: { createdAt: "desc" },
      }),
      prisma.user.count(),
    ]);
    return { data: users, total, page: params.page, limit: params.limit };
  }

  async findById(id: string): Promise<User> {
    const user = await prisma.user.findUnique({ where: { id } });
    if (!user) throw ApiError.notFound(`User with ID ${id} not found`);
    return user;
  }

  async findByEmail(email: string): Promise<User | null> {
    return prisma.user.findUnique({ where: { email } });
  }

  async create(data: { email: string; password: string; name: string }): Promise<User> {
    return prisma.user.create({ data });
  }

  async update(id: string, data: Partial<User>): Promise<User> {
    return prisma.user.update({ where: { id }, data });
  }

  async delete(id: string): Promise<void> {
    await prisma.user.delete({ where: { id } });
  }
}
```

### Drizzle Alternative

```typescript
// models/drizzle/schema.ts
import { pgTable, uuid, varchar, timestamp, pgEnum } from "drizzle-orm/pg-core";

export const roleEnum = pgEnum("role", ["user", "admin"]);

export const users = pgTable("users", {
  id: uuid("id").defaultRandom().primaryKey(),
  email: varchar("email", { length: 255 }).notNull().unique(),
  password: varchar("password", { length: 255 }).notNull(),
  name: varchar("name", { length: 100 }).notNull(),
  role: roleEnum("role").default("user").notNull(),
  createdAt: timestamp("created_at").defaultNow().notNull(),
  updatedAt: timestamp("updated_at").defaultNow().notNull(),
});
```

---

## Security Practices

### Essential Security Middleware

```typescript
import helmet from "helmet";
import cors from "cors";
import rateLimit from "express-rate-limit";

// Helmet sets security headers (X-Content-Type-Options, Strict-Transport-Security, etc.)
app.use(helmet());

// CORS - restrict origins in production
app.use(cors({
  origin: env.NODE_ENV === "production" ? env.CORS_ORIGIN : "*",
  methods: ["GET", "POST", "PUT", "PATCH", "DELETE"],
  allowedHeaders: ["Content-Type", "Authorization"],
  credentials: true,
}));

// Rate limiting
const limiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 100,                  // 100 requests per window
  standardHeaders: true,
  legacyHeaders: false,
  message: { success: false, message: "Too many requests, please try again later" },
});
app.use("/api", limiter);

// Stricter limiter for auth routes
const authLimiter = rateLimit({ windowMs: 15 * 60 * 1000, max: 10 });
app.use("/api/v1/auth", authLimiter);
```

### OWASP Checklist Items

- **Body size limits**: `express.json({ limit: "10kb" })` to prevent large payload attacks.
- **Parameterized queries**: Always use ORM parameterized queries; never interpolate user input into SQL.
- **No stack traces in production**: The error handler must omit `err.stack` when `NODE_ENV === "production"`.
- **Dependency auditing**: Run `npm audit` regularly.
- **HTTPS only**: Enforce via reverse proxy (nginx) or `app.use(helmet.hsts())`.
- **Sanitize HTML**: Use a library like `sanitize-html` or `DOMPurify` if accepting rich text.
- **Cookie security**: Set `httpOnly: true`, `secure: true`, `sameSite: "strict"` on session cookies.

---

## TypeScript Patterns

### Extending the Request Type

```typescript
// types/express.d.ts
declare namespace Express {
  interface Request {
    user?: {
      userId: string;
      role: string;
    };
  }
}
```

### Typed Route Parameters

```typescript
import { Request, Response } from "express";

interface UserParams {
  id: string;
}

interface PaginationQuery {
  page?: string;
  limit?: string;
  sort?: string;
}

// Usage in controller
const getUser = async (req: Request<UserParams, unknown, unknown, PaginationQuery>, res: Response) => {
  const { id } = req.params;  // string, typed
  // ...
};
```

### Typed Middleware

```typescript
import { RequestHandler } from "express";

const requireRole = (role: string): RequestHandler => {
  return (req, _res, next) => {
    if (req.user?.role !== role) {
      throw ApiError.forbidden("Insufficient permissions");
    }
    next();
  };
};
```

---

## Testing

### Integration Test with Supertest

```typescript
// tests/integration/user.test.ts
import { describe, it, expect, beforeAll, afterAll } from "vitest";
import request from "supertest";
import { app } from "../../src/app";
import { prisma } from "../../src/config/database";

describe("GET /api/v1/users", () => {
  let token: string;

  beforeAll(async () => {
    // Seed a test user and get token
    const res = await request(app)
      .post("/api/v1/auth/login")
      .send({ email: "admin@test.com", password: "Password123" });
    token = res.body.data.accessToken;
  });

  afterAll(async () => {
    await prisma.$disconnect();
  });

  it("should return paginated users", async () => {
    const res = await request(app)
      .get("/api/v1/users?page=1&limit=10")
      .set("Authorization", `Bearer ${token}`);

    expect(res.status).toBe(200);
    expect(res.body.success).toBe(true);
    expect(res.body.data).toHaveProperty("data");
    expect(res.body.data).toHaveProperty("total");
  });

  it("should return 401 without token", async () => {
    const res = await request(app).get("/api/v1/users");
    expect(res.status).toBe(401);
  });
});
```

### Unit Test for a Service

```typescript
// tests/unit/services/user.service.test.ts
import { describe, it, expect, vi, beforeEach } from "vitest";
import { UserService } from "../../../src/services/user.service";
import { UserRepository } from "../../../src/repositories/user.repository";

vi.mock("../../../src/repositories/user.repository");

describe("UserService", () => {
  let service: UserService;
  let mockRepo: vi.Mocked<UserRepository>;

  beforeEach(() => {
    mockRepo = new UserRepository() as vi.Mocked<UserRepository>;
    service = new UserService();
    (service as any).userRepo = mockRepo;
  });

  it("should throw NotFound when user does not exist", async () => {
    mockRepo.findById.mockRejectedValue(new Error("Not found"));
    await expect(service.findById("nonexistent")).rejects.toThrow();
  });
});
```

### Running Tests

```bash
# All tests
npm test

# With coverage
npm run test:coverage

# Watch mode
npm run test:watch

# Single file
npx vitest run tests/integration/user.test.ts
```

---

## Logging

### Pino Configuration

```typescript
// config/logger.ts
import pino from "pino";
import { env } from "./env";

export const logger = pino({
  level: env.LOG_LEVEL || "info",
  transport:
    env.NODE_ENV === "development"
      ? { target: "pino-pretty", options: { colorize: true, translateTime: "SYS:standard" } }
      : undefined,
  redact: ["req.headers.authorization", "req.body.password"],
});
```

### HTTP Request Logging

```typescript
// middleware/requestLogger.ts
import { pinoHttp } from "pino-http";
import { logger } from "../config/logger";

export const requestLogger = pinoHttp({
  logger,
  autoLogging: {
    ignore: (req) => req.url === "/health",
  },
});
```

---

## Environment Configuration

### Env Validation with Zod

```typescript
// config/env.ts
import { z } from "zod";
import dotenv from "dotenv";

dotenv.config();

const envSchema = z.object({
  NODE_ENV: z.enum(["development", "production", "test"]).default("development"),
  PORT: z.coerce.number().default(3000),
  DATABASE_URL: z.string().url(),
  JWT_SECRET: z.string().min(32, "JWT_SECRET must be at least 32 characters"),
  JWT_REFRESH_SECRET: z.string().min(32),
  JWT_EXPIRES_IN: z.string().default("15m"),
  CORS_ORIGIN: z.string().default("*"),
  LOG_LEVEL: z.enum(["fatal", "error", "warn", "info", "debug", "trace"]).default("info"),
});

const parsed = envSchema.safeParse(process.env);

if (!parsed.success) {
  console.error("Invalid environment variables:", parsed.error.flatten().fieldErrors);
  process.exit(1);
}

export const env = parsed.data;
export type Env = z.infer<typeof envSchema>;
```

---

## API Design

### Standard Response Format

```json
// Success
{
  "success": true,
  "data": { ... },
  "meta": {
    "page": 1,
    "limit": 20,
    "total": 150,
    "totalPages": 8
  }
}

// Error
{
  "success": false,
  "message": "Validation failed",
  "errors": [
    { "path": "email", "message": "Invalid email address" }
  ]
}
```

### Pagination, Filtering, and Sorting

```typescript
// validators/common.validator.ts
import { z } from "zod";

export const paginationSchema = z.object({
  page: z.coerce.number().int().positive().default(1),
  limit: z.coerce.number().int().min(1).max(100).default(20),
  sort: z.string().optional(),      // e.g., "createdAt:desc"
  search: z.string().optional(),    // full-text search term
});

export type PaginationQuery = z.infer<typeof paginationSchema>;
```

```typescript
// utils/pagination.ts
export function buildPaginationMeta(total: number, page: number, limit: number) {
  return {
    page,
    limit,
    total,
    totalPages: Math.ceil(total / limit),
    hasNext: page * limit < total,
    hasPrev: page > 1,
  };
}
```

---

## Performance

### Compression

```typescript
import compression from "compression";
app.use(compression());
```

### Clustering

```typescript
// server.ts
import cluster from "node:cluster";
import os from "node:os";
import { app } from "./app";
import { env } from "./config/env";

if (cluster.isPrimary && env.NODE_ENV === "production") {
  const cpuCount = os.cpus().length;
  for (let i = 0; i < cpuCount; i++) {
    cluster.fork();
  }
  cluster.on("exit", (worker) => {
    console.log(`Worker ${worker.process.pid} died, spawning replacement`);
    cluster.fork();
  });
} else {
  app.listen(env.PORT, () => {
    console.log(`Server running on port ${env.PORT} (PID: ${process.pid})`);
  });
}
```

### Connection Pooling

Prisma manages connection pooling automatically. Configure via `DATABASE_URL`:

```
DATABASE_URL="postgresql://user:pass@host:5432/db?connection_limit=20&pool_timeout=10"
```

---

## Deployment

### Dockerfile

```dockerfile
FROM node:20-alpine AS builder
WORKDIR /app
COPY package*.json ./
RUN npm ci
COPY . .
RUN npx prisma generate
RUN npm run build

FROM node:20-alpine AS runner
WORKDIR /app
ENV NODE_ENV=production
COPY --from=builder /app/dist ./dist
COPY --from=builder /app/node_modules ./node_modules
COPY --from=builder /app/package.json ./
COPY --from=builder /app/prisma ./prisma
EXPOSE 3000
CMD ["node", "dist/server.js"]
```

### Health Check Endpoint

```typescript
// routes/index.ts
router.get("/health", (_req, res) => {
  res.json({ status: "ok", uptime: process.uptime(), timestamp: new Date().toISOString() });
});
```

### PM2 Ecosystem File

```javascript
// ecosystem.config.js
module.exports = {
  apps: [
    {
      name: "api",
      script: "dist/server.js",
      instances: "max",
      exec_mode: "cluster",
      env_production: { NODE_ENV: "production" },
    },
  ],
};
```

---

## Common Anti-Patterns (Avoid These)

1. **Business logic in controllers** -- Move all business logic to service classes.
2. **Calling `res.json()` after `res.json()`** -- Always `return` after sending a response, or use `if/else` to guarantee a single response per request.
3. **Missing `next(err)` in error paths** -- Unforwarded errors cause requests to hang.
4. **Not validating environment variables** -- The server should crash at startup if required variables are missing.
5. **Using `any` as an escape hatch** -- Define proper types for request bodies, params, and query strings.
6. **Importing `PrismaClient` in every file** -- Create a single shared instance in `config/database.ts`.
7. **Hardcoding secrets** -- Use environment variables for all secrets; never commit `.env`.
8. **Synchronous file operations** -- Always use `fs/promises` or async variants.
9. **No request body size limit** -- Always set `express.json({ limit: "10kb" })`.
10. **Catching errors silently** -- Log every caught error; never use empty `catch` blocks.
11. **No graceful shutdown** -- Handle `SIGTERM` and `SIGINT` to close database connections and drain active requests.
12. **Monolithic route files** -- Split routes by resource; use `Router()` for modularity.
13. **Not using HTTP status codes correctly** -- `201` for created, `204` for no content, `409` for conflict, etc.
14. **Mutating `req`/`res` globals** -- Avoid monkey-patching Express objects outside type-safe augmentation.

---

## Graceful Shutdown

```typescript
// server.ts (after app.listen)
import { prisma } from "./config/database";
import { logger } from "./config/logger";

const server = app.listen(env.PORT, () => {
  logger.info(`Server listening on port ${env.PORT}`);
});

function gracefulShutdown(signal: string) {
  logger.info(`Received ${signal}. Shutting down gracefully...`);
  server.close(async () => {
    await prisma.$disconnect();
    logger.info("Database connections closed. Process exiting.");
    process.exit(0);
  });

  // Force shutdown after timeout
  setTimeout(() => {
    logger.error("Could not close connections in time, forcefully shutting down");
    process.exit(1);
  }, 10_000);
}

process.on("SIGTERM", () => gracefulShutdown("SIGTERM"));
process.on("SIGINT", () => gracefulShutdown("SIGINT"));
```

---

## Git Conventions

| Type       | Format                                    | Example                                        |
| ---------- | ----------------------------------------- | ---------------------------------------------- |
| Commit msg | `<type>(<scope>): <description>`          | `feat(auth): add refresh token rotation`       |
| Branch     | `<type>/<ticket>-<description>`           | `feat/API-42-add-user-search`                  |
| Types      | `feat`, `fix`, `refactor`, `docs`, `test`, `chore` | `fix(user): handle duplicate email error` |

### Commit Types

- **feat**: New feature or endpoint
- **fix**: Bug fix
- **refactor**: Code restructuring without behavior change
- **docs**: Documentation only
- **test**: Adding or updating tests
- **chore**: Tooling, dependencies, CI config

---

## Quick Reference Commands

```bash
# Development
npm run dev              # Start with hot-reload (tsx/nodemon)
npm run build            # Compile TypeScript
npm start                # Run compiled output

# Database
npx prisma migrate dev   # Create and apply migrations
npx prisma generate      # Regenerate Prisma client
npx prisma studio        # Open Prisma GUI

# Testing
npm test                 # Run all tests
npm run test:coverage    # Coverage report
npm run test:watch       # Watch mode

# Linting
npm run lint             # ESLint check
npm run lint:fix         # Auto-fix lint issues
npm run format           # Prettier format
```
