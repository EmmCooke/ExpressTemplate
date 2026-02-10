# Express.js - Comprehensive Guide

## What is Express?

Express is a **minimal, unopinionated web framework for Node.js**. It provides a thin layer of fundamental web application features without obscuring the Node.js APIs you already know. Unlike full-stack frameworks such as Rails or Django that ship with an ORM, template engine, and authentication system out of the box, Express gives you a routing layer and a middleware pipeline and lets you choose every other piece of the stack yourself.

At its core, Express does three things:

1. **Routing** -- Maps incoming HTTP requests (method + URL) to handler functions.
2. **Middleware pipeline** -- Passes every request through a chain of functions that can inspect, transform, or respond to the request before it reaches the final handler.
3. **HTTP utility methods** -- Wraps the raw Node.js `http.ServerResponse` with convenience methods like `res.json()`, `res.send()`, `res.redirect()`, and `res.status()`.

Express is the most widely used Node.js server framework. It powers APIs, server-rendered web apps, proxy layers, and microservices. Its simplicity makes it an excellent foundation for projects of any size, from quick prototypes to production systems handling millions of requests.

---

## Getting Started

### Project Initialization

```bash
mkdir my-express-api && cd my-express-api
npm init -y
```

### Installing Dependencies

```bash
# Core
npm install express

# TypeScript
npm install -D typescript tsx @types/node @types/express

# Common production dependencies
npm install zod dotenv helmet cors compression pino pino-http jsonwebtoken bcryptjs
npm install -D @types/jsonwebtoken @types/bcryptjs @types/cors @types/compression
```

### TypeScript Configuration

Create a `tsconfig.json` at the project root:

```json
{
  "compilerOptions": {
    "target": "ES2022",
    "module": "Node16",
    "moduleResolution": "Node16",
    "lib": ["ES2022"],
    "outDir": "./dist",
    "rootDir": "./src",
    "strict": true,
    "esModuleInterop": true,
    "skipLibCheck": true,
    "forceConsistentCasingInFileNames": true,
    "resolveJsonModule": true,
    "declaration": true,
    "declarationMap": true,
    "sourceMap": true,
    "noUnusedLocals": true,
    "noUnusedParameters": true,
    "noImplicitReturns": true,
    "noFallthroughCasesInSwitch": true
  },
  "include": ["src/**/*"],
  "exclude": ["node_modules", "dist", "tests"]
}
```

### Package Scripts

```json
{
  "scripts": {
    "dev": "tsx watch src/server.ts",
    "build": "tsc",
    "start": "node dist/server.js",
    "lint": "eslint src/",
    "lint:fix": "eslint src/ --fix",
    "format": "prettier --write src/",
    "test": "vitest run",
    "test:watch": "vitest",
    "test:coverage": "vitest run --coverage"
  }
}
```

### Minimal Application

```typescript
// src/app.ts
import express, { Request, Response } from "express";

const app = express();

// Parse JSON request bodies
app.use(express.json());

// A simple route
app.get("/", (_req: Request, res: Response) => {
  res.json({ message: "Hello, Express!" });
});

export { app };
```

```typescript
// src/server.ts
import { app } from "./app";

const PORT = process.env.PORT || 3000;

app.listen(PORT, () => {
  console.log(`Server is running on http://localhost:${PORT}`);
});
```

Run in development with hot-reload:

```bash
npm run dev
```

---

## Core Concepts

### The Request/Response Cycle

When a client sends an HTTP request to an Express server, the following happens:

1. **Node.js receives the raw TCP connection** and creates `IncomingMessage` (request) and `ServerResponse` (response) objects.
2. **Express wraps these objects** with additional properties and methods (`req.params`, `req.query`, `req.body`, `res.json()`, `res.status()`, etc.).
3. **The middleware pipeline executes.** Each middleware function is called in the order it was registered with `app.use()` or route-specific methods. Each middleware can:
   - Read or modify `req` and `res`.
   - End the cycle by sending a response (`res.json()`, `res.send()`, etc.).
   - Pass control to the next middleware by calling `next()`.
4. **A route handler matches** the method and path, runs its handler, and sends a response.
5. **If no route matches**, control falls through to 404 handling middleware.
6. **If any middleware or route throws or calls `next(err)`**, Express skips to the next error-handling middleware (a function with four parameters).

This pipeline architecture is the single most important concept in Express. Every feature -- logging, authentication, validation, CORS, compression -- is implemented as middleware.

### How Middleware Works

A middleware function has this signature:

```typescript
(req: Request, res: Response, next: NextFunction) => void
```

- `req` -- The request object, enriched by Express.
- `res` -- The response object, enriched by Express.
- `next` -- A function that, when called, passes control to the next middleware in the stack. If called with an argument (`next(err)`), Express skips to error-handling middleware.

Middleware is registered with `app.use()`:

```typescript
// Runs for ALL routes and methods
app.use((req, res, next) => {
  console.log(`${req.method} ${req.url}`);
  next(); // Pass control to the next middleware
});
```

You can also restrict middleware to specific paths:

```typescript
// Runs only for paths starting with /api
app.use("/api", someMiddleware);
```

If a middleware function does **not** call `next()` and does **not** send a response, the request will hang indefinitely. This is a common source of bugs.

---

## Routing Deep Dive

### HTTP Methods

Express provides a method for each HTTP verb:

```typescript
app.get("/users", handler);      // Read
app.post("/users", handler);     // Create
app.put("/users/:id", handler);  // Replace
app.patch("/users/:id", handler);// Partial update
app.delete("/users/:id", handler);// Delete
app.options("/users", handler);  // CORS preflight
app.head("/users", handler);     // Like GET but no body

// Match all methods
app.all("/users", handler);
```

### Route Parameters

Route parameters are named segments in the URL prefixed with a colon:

```typescript
app.get("/users/:userId/posts/:postId", (req, res) => {
  // req.params = { userId: "42", postId: "7" }
  const { userId, postId } = req.params;
  res.json({ userId, postId });
});
```

Parameters are always strings. Convert them to numbers or validate them as needed.

You can constrain parameters with regular expressions:

```typescript
// Only match numeric IDs
app.get("/users/:id(\\d+)", (req, res) => {
  res.json({ id: Number(req.params.id) });
});
```

### Query Strings

Query parameters are parsed automatically and available on `req.query`:

```typescript
// GET /search?q=express&page=2&limit=10
app.get("/search", (req, res) => {
  const { q, page, limit } = req.query;
  // q = "express", page = "2", limit = "10"
  // All values are strings (or undefined)
  res.json({ q, page, limit });
});
```

### The Router Object

`express.Router()` creates a modular, mountable route handler. Think of it as a "mini Express app" that only handles routing. This is the primary mechanism for organizing routes into separate files:

```typescript
// routes/users.ts
import { Router } from "express";

const router = Router();

router.get("/", (req, res) => {
  res.json({ message: "List all users" });
});

router.get("/:id", (req, res) => {
  res.json({ message: `Get user ${req.params.id}` });
});

router.post("/", (req, res) => {
  res.status(201).json({ message: "Create user", data: req.body });
});

router.put("/:id", (req, res) => {
  res.json({ message: `Update user ${req.params.id}` });
});

router.delete("/:id", (req, res) => {
  res.status(204).send();
});

export { router as userRoutes };
```

Mount the router on the main app:

```typescript
// app.ts
import { userRoutes } from "./routes/users";

app.use("/api/v1/users", userRoutes);
```

Now all routes defined in `userRoutes` are prefixed with `/api/v1/users`. A `GET` to `/api/v1/users/42` will match the `router.get("/:id")` handler.

### Route Chaining

You can chain multiple handlers for the same route using `route()`:

```typescript
router
  .route("/")
  .get(getUsers)
  .post(validateBody, createUser);

router
  .route("/:id")
  .get(getUserById)
  .put(validateBody, updateUser)
  .delete(deleteUser);
```

This keeps related handlers grouped together and reduces repetition of the path string.

### Nested Routers

Routers can mount other routers for deeply nested resource URLs:

```typescript
// routes/posts.ts
const postRouter = Router({ mergeParams: true });

postRouter.get("/", (req, res) => {
  // req.params.userId is available because of mergeParams
  res.json({ message: `Posts for user ${req.params.userId}` });
});

export { postRouter };

// routes/users.ts
import { postRouter } from "./posts";

router.use("/:userId/posts", postRouter);
```

The `mergeParams: true` option is essential -- without it, `req.params.userId` would be `undefined` inside the nested router.

---

## Middleware System

Middleware is the backbone of Express. There are five categories.

### 1. Application-Level Middleware

Bound to the `app` instance using `app.use()` or `app.METHOD()`. Runs for every matching request.

```typescript
// Runs for all requests
app.use((req, res, next) => {
  req.requestTime = Date.now();
  next();
});

// Runs only for GET /users
app.get("/users", (req, res, next) => {
  // This is also middleware; it just happens to also be a terminal handler
  res.json({ users: [] });
});
```

### 2. Router-Level Middleware

Bound to a `Router` instance. Works identically to application-level middleware but is scoped to that router.

```typescript
const router = Router();

// Runs for every request hitting this router
router.use((req, res, next) => {
  console.log("Router middleware:", req.method, req.url);
  next();
});

router.get("/", handler);
```

### 3. Error-Handling Middleware

Defined with **four** parameters. Express identifies it as an error handler by the arity of the function (it checks `fn.length === 4`).

```typescript
app.use((err: Error, req: Request, res: Response, next: NextFunction) => {
  console.error(err.stack);
  res.status(500).json({ error: "Something went wrong" });
});
```

Key rules:
- Must be registered **after** all routes and other middleware.
- Must have exactly four parameters, even if you do not use all of them. Omitting `next` changes the function's arity and Express will not treat it as an error handler.
- You can have multiple error handlers chained. Call `next(err)` to pass to the next one.

### 4. Built-In Middleware

Express 5 ships with three built-in middleware functions:

```typescript
// Parse JSON bodies
app.use(express.json());

// Parse URL-encoded bodies (form submissions)
app.use(express.urlencoded({ extended: true }));

// Serve static files from a directory
app.use(express.static("public"));
```

`express.json()` and `express.urlencoded()` are wrappers around the `body-parser` library (which is bundled with Express since version 4.16).

### 5. Third-Party Middleware

The Express ecosystem has hundreds of middleware packages. Here are the most commonly used:

| Package              | Purpose                                | Example                                      |
| -------------------- | -------------------------------------- | -------------------------------------------- |
| `helmet`             | Security HTTP headers                  | `app.use(helmet())`                          |
| `cors`               | Cross-Origin Resource Sharing          | `app.use(cors({ origin: "..." }))`           |
| `compression`        | Gzip/Brotli response compression       | `app.use(compression())`                     |
| `morgan`             | HTTP request logging (dev-friendly)    | `app.use(morgan("dev"))`                     |
| `pino-http`          | HTTP request logging (structured/JSON) | `app.use(pinoHttp())`                        |
| `express-rate-limit` | Rate limiting                          | `app.use(rateLimit({ windowMs: 900000 }))`   |
| `cookie-parser`      | Parse Cookie header                    | `app.use(cookieParser())`                    |
| `express-session`    | Server-side session management         | `app.use(session({ secret: "..." }))`        |
| `multer`             | Multipart/form-data file uploads       | `upload.single("avatar")`                    |
| `passport`           | Authentication strategies              | `app.use(passport.initialize())`             |

### Middleware Execution Order

Middleware runs in the order it is registered. This order matters:

```typescript
// CORRECT ORDER
app.use(helmet());           // 1. Security headers first
app.use(cors());             // 2. CORS before any route processing
app.use(compression());      // 3. Compress responses
app.use(express.json());     // 4. Parse body before routes read it
app.use(requestLogger);      // 5. Log the request
app.use(rateLimiter);        // 6. Rate limit before heavy processing
app.use("/api", routes);     // 7. Application routes
app.use(notFoundHandler);    // 8. 404 for unmatched routes
app.use(errorHandler);       // 9. Error handler always last
```

---

## Request and Response Objects

### The Request Object (`req`)

The request object represents the HTTP request. Express extends the native Node.js `IncomingMessage` with these key properties:

```typescript
// Route parameters -- from the URL path
req.params        // { id: "42" }        for route "/users/:id"

// Query string
req.query         // { page: "1" }       for URL "/users?page=1"

// Parsed request body (requires body-parsing middleware)
req.body          // { name: "Alice" }   from JSON body

// HTTP headers
req.headers       // { "content-type": "application/json", ... }
req.get("Content-Type")  // "application/json"

// The full URL
req.url           // "/users?page=1"
req.originalUrl   // "/api/v1/users?page=1" (before Router prefix stripping)
req.path          // "/users"
req.baseUrl       // "/api/v1" (the mounted path of the Router)

// HTTP method
req.method        // "GET", "POST", etc.

// Protocol and host
req.protocol      // "https"
req.hostname      // "example.com"
req.ip            // "127.0.0.1"

// Cookies (with cookie-parser)
req.cookies       // { session: "abc123" }

// Check accepted content types
req.accepts("json")      // "json" or false
req.is("application/json") // "application/json" or false
```

### The Response Object (`res`)

The response object represents the HTTP response. Express extends `ServerResponse` with:

```typescript
// Set status code
res.status(201)

// Send JSON response
res.json({ success: true, data: user })

// Send text/HTML response
res.send("<h1>Hello</h1>")
res.send("plain text")

// Send file
res.sendFile("/absolute/path/to/file.pdf")

// Download file
res.download("/path/to/file.pdf", "report.pdf")

// Redirect
res.redirect("/login")
res.redirect(301, "/new-url")

// Set headers
res.set("X-Custom-Header", "value")
res.set({ "X-One": "1", "X-Two": "2" })

// Set cookies (with cookie-parser)
res.cookie("token", "abc123", {
  httpOnly: true,
  secure: true,
  sameSite: "strict",
  maxAge: 3600000, // 1 hour in milliseconds
});
res.clearCookie("token");

// Set content type
res.type("json")     // Content-Type: application/json
res.type("html")     // Content-Type: text/html

// Chain methods
res.status(201).json({ id: 1, name: "Alice" });

// End without body
res.status(204).end();
res.sendStatus(204);  // Shorthand: sets status and sends status text as body
```

**Important:** You can only send one response per request. Calling `res.json()` or `res.send()` more than once will throw an error (`Cannot set headers after they are sent to the client`). Always `return` after sending a response, especially in middleware with conditional logic.

---

## Error Handling Patterns

### Express 5 Automatic Promise Rejection Handling

Express 5 (unlike Express 4) automatically catches rejected promises and forwards them to the error handler:

```typescript
// Express 5: This works without a wrapper
app.get("/users/:id", async (req, res) => {
  const user = await UserService.findById(req.params.id); // If this throws, Express catches it
  res.json(user);
});
```

In Express 4, an unhandled promise rejection would crash the process or hang the request. You would need a wrapper:

```typescript
// Express 4 pattern (still useful for explicit error transforms)
function asyncHandler(fn: (req: Request, res: Response, next: NextFunction) => Promise<void>) {
  return (req: Request, res: Response, next: NextFunction) => {
    Promise.resolve(fn(req, res, next)).catch(next);
  };
}

app.get("/users/:id", asyncHandler(async (req, res) => {
  const user = await UserService.findById(req.params.id);
  res.json(user);
}));
```

### Custom Error Classes

Create a hierarchy of error classes for different HTTP error scenarios:

```typescript
// utils/ApiError.ts
export class ApiError extends Error {
  constructor(
    public statusCode: number,
    message: string,
    public errors?: { path: string; message: string }[],
    public isOperational = true
  ) {
    super(message);
    Object.setPrototypeOf(this, ApiError.prototype);
  }

  static badRequest(msg: string) { return new ApiError(400, msg); }
  static unauthorized(msg = "Unauthorized") { return new ApiError(401, msg); }
  static forbidden(msg = "Forbidden") { return new ApiError(403, msg); }
  static notFound(msg = "Not found") { return new ApiError(404, msg); }
  static conflict(msg: string) { return new ApiError(409, msg); }
  static tooMany(msg = "Too many requests") { return new ApiError(429, msg); }
  static internal(msg = "Internal server error") { return new ApiError(500, msg, undefined, false); }
}
```

### Centralized Error Handler

```typescript
// middleware/errorHandler.ts
import { Request, Response, NextFunction } from "express";
import { ZodError } from "zod";
import { ApiError } from "../utils/ApiError";
import { logger } from "../config/logger";
import { env } from "../config/env";

export function errorHandler(err: Error, _req: Request, res: Response, _next: NextFunction): void {
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

  // Known operational errors
  if (err instanceof ApiError) {
    res.status(err.statusCode).json({
      success: false,
      message: err.message,
      ...(err.errors && { errors: err.errors }),
    });
    return;
  }

  // Unexpected errors
  logger.error({ err }, "Unhandled error");

  res.status(500).json({
    success: false,
    message: "Internal Server Error",
    ...(env.NODE_ENV === "development" && { stack: err.stack }),
  });
}
```

### 404 Handler

Place this **after** all routes but **before** the error handler:

```typescript
// middleware/notFound.ts
import { Request, Response } from "express";

export function notFoundHandler(_req: Request, res: Response): void {
  res.status(404).json({
    success: false,
    message: `Route ${_req.method} ${_req.originalUrl} not found`,
  });
}
```

---

## Template Engines

Although most Express projects today are JSON APIs, Express can render HTML using template engines. Popular choices include EJS, Pug (Jade), and Handlebars.

```typescript
// Setup
app.set("view engine", "ejs");
app.set("views", path.join(__dirname, "views"));

// Render a template
app.get("/dashboard", (req, res) => {
  res.render("dashboard", {
    title: "Dashboard",
    user: req.user,
    stats: { totalUsers: 150, activeToday: 42 },
  });
});
```

```html
<!-- views/dashboard.ejs -->
<!DOCTYPE html>
<html>
<head><title><%= title %></title></head>
<body>
  <h1>Welcome, <%= user.name %></h1>
  <p>Total users: <%= stats.totalUsers %></p>
  <p>Active today: <%= stats.activeToday %></p>
</body>
</html>
```

For API-only projects (which is the common case for this template), template engines are unnecessary. The server responds exclusively with JSON.

---

## Static Files

Express can serve static files (HTML, CSS, images, JavaScript) from a directory:

```typescript
import path from "node:path";

// Serve files from the "public" directory
app.use(express.static(path.join(__dirname, "..", "public")));

// With a virtual path prefix
app.use("/static", express.static(path.join(__dirname, "..", "public")));
// A file at public/images/logo.png is now available at /static/images/logo.png

// Multiple static directories (checked in order)
app.use(express.static("public"));
app.use(express.static("uploads"));
```

For production, it is almost always better to serve static files through a reverse proxy like nginx or a CDN rather than through Express directly.

---

## Security Best Practices

### Helmet

Helmet sets various HTTP headers to help protect your app:

```typescript
import helmet from "helmet";

app.use(helmet());
// Sets: X-Content-Type-Options, X-Frame-Options, X-XSS-Protection,
//       Strict-Transport-Security, Content-Security-Policy, and more
```

You can configure individual headers:

```typescript
app.use(helmet({
  contentSecurityPolicy: {
    directives: {
      defaultSrc: ["'self'"],
      scriptSrc: ["'self'", "'unsafe-inline'"],
      styleSrc: ["'self'", "'unsafe-inline'"],
    },
  },
  crossOriginEmbedderPolicy: false,
}));
```

### CORS

Cross-Origin Resource Sharing controls which origins can access your API:

```typescript
import cors from "cors";

// Allow all origins (development)
app.use(cors());

// Restrict to specific origins (production)
app.use(cors({
  origin: ["https://myapp.com", "https://admin.myapp.com"],
  methods: ["GET", "POST", "PUT", "PATCH", "DELETE"],
  allowedHeaders: ["Content-Type", "Authorization"],
  exposedHeaders: ["X-Total-Count"],
  credentials: true,       // Allow cookies
  maxAge: 86400,           // Cache preflight for 24 hours
}));

// Dynamic origin validation
app.use(cors({
  origin: (origin, callback) => {
    const allowedOrigins = ["https://myapp.com", "https://admin.myapp.com"];
    if (!origin || allowedOrigins.includes(origin)) {
      callback(null, true);
    } else {
      callback(new Error("Not allowed by CORS"));
    }
  },
}));
```

### Rate Limiting

Prevent brute-force and denial-of-service attacks:

```typescript
import rateLimit from "express-rate-limit";

// Global rate limit
const globalLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,  // 15 minutes
  max: 100,                   // 100 requests per window
  standardHeaders: true,      // Return rate limit info in headers
  legacyHeaders: false,       // Disable X-RateLimit-* headers
  message: { success: false, message: "Too many requests" },
});
app.use(globalLimiter);

// Strict limiter for authentication routes
const authLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 10,
  message: { success: false, message: "Too many login attempts" },
});
app.use("/api/v1/auth", authLimiter);
```

### Input Sanitization

Never trust user input. Validate and sanitize everything:

```typescript
// Use Zod for schema validation
import { z } from "zod";

const createUserSchema = z.object({
  email: z.string().email().max(255),
  name: z.string().min(1).max(100).trim(),
  bio: z.string().max(500).optional(),
});

// For HTML content, sanitize to prevent XSS
import sanitizeHtml from "sanitize-html";

const sanitizedBio = sanitizeHtml(req.body.bio, {
  allowedTags: ["b", "i", "em", "strong", "a"],
  allowedAttributes: { a: ["href"] },
});
```

### Additional Security Measures

```typescript
// Limit body size to prevent large payload attacks
app.use(express.json({ limit: "10kb" }));
app.use(express.urlencoded({ extended: true, limit: "10kb" }));

// Disable X-Powered-By header (also done by helmet)
app.disable("x-powered-by");

// Use parameterized queries (Prisma and Drizzle do this by default)
// NEVER concatenate user input into SQL strings

// Set secure cookie options
app.use(session({
  secret: env.SESSION_SECRET,
  cookie: {
    httpOnly: true,    // Not accessible via JavaScript
    secure: true,      // Only sent over HTTPS
    sameSite: "strict",// Prevents CSRF
    maxAge: 3600000,   // 1 hour
  },
  resave: false,
  saveUninitialized: false,
}));
```

---

## Authentication and Authorization

### JWT Authentication Flow

JWTs (JSON Web Tokens) are the most common authentication mechanism for Express APIs. The flow:

1. Client sends credentials (email + password) to `POST /api/v1/auth/login`.
2. Server validates credentials, creates a JWT, and returns it.
3. Client includes the JWT in the `Authorization` header of subsequent requests.
4. Server middleware verifies the JWT on protected routes.

```typescript
// services/auth.service.ts
import jwt from "jsonwebtoken";
import bcrypt from "bcryptjs";

export class AuthService {
  async login(email: string, password: string) {
    const user = await userRepo.findByEmail(email);
    if (!user) throw ApiError.unauthorized("Invalid credentials");

    const valid = await bcrypt.compare(password, user.password);
    if (!valid) throw ApiError.unauthorized("Invalid credentials");

    const accessToken = jwt.sign(
      { userId: user.id, role: user.role },
      env.JWT_SECRET,
      { expiresIn: "15m" }
    );

    const refreshToken = jwt.sign(
      { userId: user.id },
      env.JWT_REFRESH_SECRET,
      { expiresIn: "7d" }
    );

    return { accessToken, refreshToken };
  }
}
```

```typescript
// middleware/authenticate.ts
import { Request, Response, NextFunction } from "express";
import jwt from "jsonwebtoken";

export function authenticate(req: Request, _res: Response, next: NextFunction): void {
  const authHeader = req.headers.authorization;
  if (!authHeader?.startsWith("Bearer ")) {
    throw ApiError.unauthorized("No token provided");
  }

  try {
    const token = authHeader.split(" ")[1];
    const payload = jwt.verify(token, env.JWT_SECRET) as { userId: string; role: string };
    req.user = payload;
    next();
  } catch {
    throw ApiError.unauthorized("Invalid or expired token");
  }
}
```

### Role-Based Authorization

```typescript
// middleware/authorize.ts
export function authorize(...roles: string[]) {
  return (req: Request, _res: Response, next: NextFunction): void => {
    if (!req.user) throw ApiError.unauthorized();
    if (!roles.includes(req.user.role)) throw ApiError.forbidden();
    next();
  };
}

// Usage in routes
router.delete("/:id", authenticate, authorize("admin"), controller.deleteUser);
```

### Passport.js Integration

Passport provides a unified API for different authentication strategies (local, OAuth, SAML, etc.):

```typescript
import passport from "passport";
import { Strategy as LocalStrategy } from "passport-local";
import { Strategy as JwtStrategy, ExtractJwt } from "passport-jwt";

// Local strategy (username/password)
passport.use(new LocalStrategy(
  { usernameField: "email" },
  async (email, password, done) => {
    try {
      const user = await userRepo.findByEmail(email);
      if (!user || !(await bcrypt.compare(password, user.password))) {
        return done(null, false, { message: "Invalid credentials" });
      }
      return done(null, user);
    } catch (err) {
      return done(err);
    }
  }
));

// JWT strategy
passport.use(new JwtStrategy(
  {
    jwtFromRequest: ExtractJwt.fromAuthHeaderAsBearerToken(),
    secretOrKey: env.JWT_SECRET,
  },
  async (payload, done) => {
    try {
      const user = await userRepo.findById(payload.userId);
      return done(null, user || false);
    } catch (err) {
      return done(err);
    }
  }
));

// Usage
app.use(passport.initialize());

router.post("/login", passport.authenticate("local", { session: false }), (req, res) => {
  const token = jwt.sign({ userId: req.user.id }, env.JWT_SECRET, { expiresIn: "15m" });
  res.json({ token });
});

router.get("/profile", passport.authenticate("jwt", { session: false }), (req, res) => {
  res.json(req.user);
});
```

---

## Database Integration

### Prisma

Prisma is a type-safe ORM that generates a client from your schema:

```prisma
// prisma/schema.prisma
generator client {
  provider = "prisma-client-js"
}

datasource db {
  provider = "postgresql"
  url      = env("DATABASE_URL")
}

model User {
  id        String   @id @default(uuid())
  email     String   @unique
  password  String
  name      String
  role      Role     @default(USER)
  posts     Post[]
  createdAt DateTime @default(now()) @map("created_at")
  updatedAt DateTime @updatedAt @map("updated_at")

  @@map("users")
}

model Post {
  id        String   @id @default(uuid())
  title     String
  content   String
  published Boolean  @default(false)
  author    User     @relation(fields: [authorId], references: [id])
  authorId  String   @map("author_id")
  createdAt DateTime @default(now()) @map("created_at")
  updatedAt DateTime @updatedAt @map("updated_at")

  @@map("posts")
}

enum Role {
  USER
  ADMIN
}
```

```typescript
// config/database.ts
import { PrismaClient } from "@prisma/client";

export const prisma = new PrismaClient({
  log: process.env.NODE_ENV === "development" ? ["query", "info", "warn", "error"] : ["error"],
});
```

```typescript
// Using Prisma in a service
const users = await prisma.user.findMany({
  where: { role: "USER" },
  select: { id: true, email: true, name: true },
  orderBy: { createdAt: "desc" },
  skip: 0,
  take: 20,
});
```

### Drizzle

Drizzle is a lightweight, SQL-like TypeScript ORM:

```typescript
// models/drizzle/schema.ts
import { pgTable, uuid, varchar, boolean, timestamp, pgEnum } from "drizzle-orm/pg-core";

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

export const posts = pgTable("posts", {
  id: uuid("id").defaultRandom().primaryKey(),
  title: varchar("title", { length: 255 }).notNull(),
  content: varchar("content").notNull(),
  published: boolean("published").default(false).notNull(),
  authorId: uuid("author_id").references(() => users.id).notNull(),
  createdAt: timestamp("created_at").defaultNow().notNull(),
  updatedAt: timestamp("updated_at").defaultNow().notNull(),
});
```

```typescript
// config/database.ts
import { drizzle } from "drizzle-orm/node-postgres";
import { Pool } from "pg";
import * as schema from "../models/drizzle/schema";

const pool = new Pool({ connectionString: process.env.DATABASE_URL });
export const db = drizzle(pool, { schema });
```

```typescript
// Using Drizzle in a service
import { eq, desc } from "drizzle-orm";
import { users } from "../models/drizzle/schema";

const allUsers = await db
  .select({ id: users.id, email: users.email, name: users.name })
  .from(users)
  .where(eq(users.role, "user"))
  .orderBy(desc(users.createdAt))
  .limit(20)
  .offset(0);
```

### Repository Pattern

The repository pattern abstracts data access behind a clean interface, making it easy to swap ORMs or add caching:

```typescript
// repositories/base.repository.ts
export interface Repository<T> {
  findAll(params: { page: number; limit: number }): Promise<{ data: T[]; total: number }>;
  findById(id: string): Promise<T | null>;
  create(data: Partial<T>): Promise<T>;
  update(id: string, data: Partial<T>): Promise<T>;
  delete(id: string): Promise<void>;
}
```

---

## API Design and RESTful Patterns

### URL Structure

```
GET    /api/v1/users              List users (with pagination)
GET    /api/v1/users/:id          Get a single user
POST   /api/v1/users              Create a user
PUT    /api/v1/users/:id          Replace a user
PATCH  /api/v1/users/:id          Partially update a user
DELETE /api/v1/users/:id          Delete a user
GET    /api/v1/users/:id/posts    Get posts belonging to a user
```

Guidelines:
- Use **nouns** for resources, not verbs (`/users`, not `/getUsers`).
- Use **plural** names (`/users`, not `/user`).
- Use **kebab-case** for multi-word paths (`/user-profiles`, not `/userProfiles`).
- Nest resources only one level deep (`/users/:id/posts` is fine; `/users/:id/posts/:postId/comments/:commentId` is too deep -- flatten it to `/comments/:commentId`).
- Use **query parameters** for filtering, sorting, and pagination.

### Consistent Response Format

Always return the same top-level structure:

```typescript
// Success
{
  "success": true,
  "data": { ... },          // Single object or array
  "meta": {                  // Only for paginated lists
    "page": 1,
    "limit": 20,
    "total": 150,
    "totalPages": 8,
    "hasNext": true,
    "hasPrev": false
  }
}

// Error
{
  "success": false,
  "message": "User not found",
  "errors": [               // Optional, for validation errors
    { "path": "email", "message": "Invalid email address" }
  ]
}
```

### HTTP Status Codes

Use status codes correctly:

| Code | Meaning                | When to Use                                        |
| ---- | ---------------------- | -------------------------------------------------- |
| 200  | OK                     | Successful GET, PUT, PATCH                         |
| 201  | Created                | Successful POST that creates a resource            |
| 204  | No Content             | Successful DELETE (no response body)               |
| 400  | Bad Request            | Validation errors, malformed request               |
| 401  | Unauthorized           | Missing or invalid authentication                  |
| 403  | Forbidden              | Authenticated but insufficient permissions         |
| 404  | Not Found              | Resource does not exist                            |
| 409  | Conflict               | Duplicate resource (e.g., email already exists)    |
| 422  | Unprocessable Entity   | Semantically invalid request                       |
| 429  | Too Many Requests      | Rate limit exceeded                                |
| 500  | Internal Server Error  | Unexpected server error                            |

### Pagination

```typescript
// GET /api/v1/users?page=2&limit=20&sort=createdAt:desc&search=alice

import { z } from "zod";

const paginationSchema = z.object({
  page: z.coerce.number().int().positive().default(1),
  limit: z.coerce.number().int().min(1).max(100).default(20),
  sort: z.string().optional(),
  search: z.string().optional(),
});

// In the service layer
async findAll(query: z.infer<typeof paginationSchema>) {
  const { page, limit, sort, search } = query;
  const skip = (page - 1) * limit;

  const where = search ? { name: { contains: search, mode: "insensitive" } } : {};

  const [data, total] = await Promise.all([
    prisma.user.findMany({ where, skip, take: limit, orderBy: parseSortParam(sort) }),
    prisma.user.count({ where }),
  ]);

  return {
    data,
    meta: {
      page,
      limit,
      total,
      totalPages: Math.ceil(total / limit),
      hasNext: page * limit < total,
      hasPrev: page > 1,
    },
  };
}
```

### Filtering and Sorting

```typescript
// GET /api/v1/posts?status=published&authorId=abc&sort=title:asc,createdAt:desc

function parseSortParam(sort?: string): Record<string, "asc" | "desc">[] {
  if (!sort) return [{ createdAt: "desc" }];
  return sort.split(",").map((s) => {
    const [field, direction] = s.split(":");
    return { [field]: direction === "asc" ? "asc" : "desc" };
  });
}
```

---

## Validation and Sanitization

### Zod Schemas

Zod provides runtime type validation with static type inference:

```typescript
// validators/post.validator.ts
import { z } from "zod";

export const createPostSchema = z.object({
  title: z.string().min(1, "Title is required").max(255),
  content: z.string().min(1, "Content is required"),
  published: z.boolean().default(false),
  tags: z.array(z.string().max(50)).max(10).optional(),
});

export const updatePostSchema = createPostSchema.partial();

export const postParamsSchema = z.object({
  id: z.string().uuid("Invalid post ID"),
});

// Infer TypeScript types from the schemas
export type CreatePostInput = z.infer<typeof createPostSchema>;
export type UpdatePostInput = z.infer<typeof updatePostSchema>;
```

### Validation Middleware

```typescript
// middleware/validate.ts
import { Request, Response, NextFunction } from "express";
import { ZodSchema } from "zod";

interface Schemas {
  body?: ZodSchema;
  query?: ZodSchema;
  params?: ZodSchema;
}

export function validate(schemas: Schemas) {
  return (req: Request, _res: Response, next: NextFunction): void => {
    if (schemas.params) req.params = schemas.params.parse(req.params) as any;
    if (schemas.query) req.query = schemas.query.parse(req.query) as any;
    if (schemas.body) req.body = schemas.body.parse(req.body);
    next();
    // If parse throws a ZodError, Express 5 catches it and forwards to the error handler.
    // In Express 4, wrap this in try/catch and call next(err).
  };
}

// Usage in routes
router.post(
  "/",
  authenticate,
  validate({ body: createPostSchema }),
  controller.createPost
);

router.get(
  "/:id",
  validate({ params: postParamsSchema }),
  controller.getPostById
);
```

---

## File Uploads

### Multer

Multer is the standard middleware for handling `multipart/form-data` (file uploads):

```typescript
import multer from "multer";
import path from "node:path";
import crypto from "node:crypto";

// Disk storage with custom filename
const storage = multer.diskStorage({
  destination: (_req, _file, cb) => {
    cb(null, "uploads/");
  },
  filename: (_req, file, cb) => {
    const uniqueSuffix = crypto.randomBytes(16).toString("hex");
    const ext = path.extname(file.originalname);
    cb(null, `${uniqueSuffix}${ext}`);
  },
});

// File filter
const fileFilter = (_req: any, file: Express.Multer.File, cb: multer.FileFilterCallback) => {
  const allowedMimes = ["image/jpeg", "image/png", "image/webp"];
  if (allowedMimes.includes(file.mimetype)) {
    cb(null, true);
  } else {
    cb(new ApiError(400, "Only JPEG, PNG, and WebP images are allowed"));
  }
};

const upload = multer({
  storage,
  fileFilter,
  limits: {
    fileSize: 5 * 1024 * 1024, // 5 MB
    files: 5,                   // Max 5 files
  },
});

// Single file upload
router.post("/avatar", authenticate, upload.single("avatar"), (req, res) => {
  if (!req.file) throw ApiError.badRequest("No file uploaded");
  res.json({
    success: true,
    data: {
      filename: req.file.filename,
      size: req.file.size,
      mimetype: req.file.mimetype,
    },
  });
});

// Multiple file upload
router.post("/gallery", authenticate, upload.array("photos", 5), (req, res) => {
  const files = req.files as Express.Multer.File[];
  res.json({
    success: true,
    data: files.map((f) => ({
      filename: f.filename,
      size: f.size,
    })),
  });
});
```

For production, upload files directly to cloud storage (AWS S3, Google Cloud Storage) using `multer-s3` or similar.

---

## WebSockets

Express itself does not handle WebSockets, but you can integrate WebSocket libraries with the same HTTP server.

### Socket.io

```typescript
import { createServer } from "node:http";
import { Server as SocketIOServer } from "socket.io";
import { app } from "./app";

const httpServer = createServer(app);
const io = new SocketIOServer(httpServer, {
  cors: { origin: env.CORS_ORIGIN, credentials: true },
});

// Authentication middleware for WebSockets
io.use((socket, next) => {
  const token = socket.handshake.auth.token;
  try {
    const payload = jwt.verify(token, env.JWT_SECRET);
    socket.data.user = payload;
    next();
  } catch {
    next(new Error("Authentication error"));
  }
});

io.on("connection", (socket) => {
  console.log(`User connected: ${socket.data.user.userId}`);

  socket.on("join-room", (roomId: string) => {
    socket.join(roomId);
  });

  socket.on("message", (data: { roomId: string; content: string }) => {
    io.to(data.roomId).emit("message", {
      userId: socket.data.user.userId,
      content: data.content,
      timestamp: new Date().toISOString(),
    });
  });

  socket.on("disconnect", () => {
    console.log(`User disconnected: ${socket.data.user.userId}`);
  });
});

// Use httpServer.listen() instead of app.listen()
httpServer.listen(env.PORT, () => {
  console.log(`Server running on port ${env.PORT}`);
});
```

### Native `ws` Library

For a lighter-weight solution:

```typescript
import { WebSocketServer } from "ws";
import { createServer } from "node:http";

const server = createServer(app);
const wss = new WebSocketServer({ server });

wss.on("connection", (ws, req) => {
  ws.on("message", (data) => {
    const message = JSON.parse(data.toString());
    // Broadcast to all connected clients
    wss.clients.forEach((client) => {
      if (client.readyState === WebSocket.OPEN) {
        client.send(JSON.stringify(message));
      }
    });
  });
});

server.listen(env.PORT);
```

---

## Testing

### Setup with Vitest and Supertest

```typescript
// vitest.config.ts
import { defineConfig } from "vitest/config";

export default defineConfig({
  test: {
    globals: true,
    environment: "node",
    setupFiles: ["./tests/helpers/setup.ts"],
    coverage: {
      provider: "v8",
      reporter: ["text", "lcov"],
      exclude: ["node_modules/", "tests/", "dist/"],
    },
  },
});
```

```typescript
// tests/helpers/setup.ts
import { beforeAll, afterAll } from "vitest";
import { prisma } from "../../src/config/database";

beforeAll(async () => {
  // Run migrations or seed test database
});

afterAll(async () => {
  await prisma.$disconnect();
});
```

### Integration Testing

Integration tests exercise the full request/response cycle:

```typescript
// tests/integration/auth.test.ts
import { describe, it, expect, beforeAll } from "vitest";
import request from "supertest";
import { app } from "../../src/app";

describe("Auth API", () => {
  describe("POST /api/v1/auth/register", () => {
    it("should register a new user", async () => {
      const res = await request(app)
        .post("/api/v1/auth/register")
        .send({
          email: "test@example.com",
          password: "Password123",
          name: "Test User",
        });

      expect(res.status).toBe(201);
      expect(res.body.success).toBe(true);
      expect(res.body.data).toHaveProperty("id");
      expect(res.body.data.email).toBe("test@example.com");
      expect(res.body.data).not.toHaveProperty("password");
    });

    it("should reject duplicate email", async () => {
      await request(app)
        .post("/api/v1/auth/register")
        .send({ email: "dupe@example.com", password: "Password123", name: "User" });

      const res = await request(app)
        .post("/api/v1/auth/register")
        .send({ email: "dupe@example.com", password: "Password123", name: "User" });

      expect(res.status).toBe(409);
      expect(res.body.success).toBe(false);
    });

    it("should reject invalid email", async () => {
      const res = await request(app)
        .post("/api/v1/auth/register")
        .send({ email: "not-an-email", password: "Password123", name: "User" });

      expect(res.status).toBe(400);
      expect(res.body.errors).toBeDefined();
    });
  });

  describe("POST /api/v1/auth/login", () => {
    beforeAll(async () => {
      await request(app)
        .post("/api/v1/auth/register")
        .send({ email: "login@example.com", password: "Password123", name: "Login User" });
    });

    it("should return tokens on valid credentials", async () => {
      const res = await request(app)
        .post("/api/v1/auth/login")
        .send({ email: "login@example.com", password: "Password123" });

      expect(res.status).toBe(200);
      expect(res.body.data).toHaveProperty("accessToken");
      expect(res.body.data).toHaveProperty("refreshToken");
    });

    it("should reject invalid password", async () => {
      const res = await request(app)
        .post("/api/v1/auth/login")
        .send({ email: "login@example.com", password: "WrongPassword" });

      expect(res.status).toBe(401);
    });
  });
});
```

### Unit Testing with Mocks

```typescript
// tests/unit/services/auth.service.test.ts
import { describe, it, expect, vi, beforeEach } from "vitest";
import { AuthService } from "../../../src/services/auth.service";
import bcrypt from "bcryptjs";

vi.mock("../../../src/repositories/user.repository", () => ({
  UserRepository: vi.fn().mockImplementation(() => ({
    findByEmail: vi.fn(),
    create: vi.fn(),
  })),
}));

describe("AuthService", () => {
  let authService: AuthService;

  beforeEach(() => {
    authService = new AuthService();
    vi.clearAllMocks();
  });

  describe("login", () => {
    it("should throw on non-existent user", async () => {
      (authService as any).userRepo.findByEmail.mockResolvedValue(null);
      await expect(authService.login("no@user.com", "pass")).rejects.toThrow("Invalid");
    });

    it("should throw on wrong password", async () => {
      (authService as any).userRepo.findByEmail.mockResolvedValue({
        id: "1",
        email: "user@test.com",
        password: await bcrypt.hash("correct", 12),
        role: "user",
      });
      await expect(authService.login("user@test.com", "wrong")).rejects.toThrow("Invalid");
    });
  });
});
```

### Test Commands

```bash
# Run all tests
npm test

# Run specific file
npx vitest run tests/integration/auth.test.ts

# Watch mode
npx vitest

# Coverage report
npx vitest run --coverage

# Run only unit tests
npx vitest run tests/unit/

# Run only integration tests
npx vitest run tests/integration/
```

---

## Deployment

### Docker

```dockerfile
# Dockerfile
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
RUN addgroup -g 1001 -S nodejs && adduser -S expressapp -u 1001
COPY --from=builder --chown=expressapp:nodejs /app/dist ./dist
COPY --from=builder --chown=expressapp:nodejs /app/node_modules ./node_modules
COPY --from=builder --chown=expressapp:nodejs /app/package.json ./
COPY --from=builder --chown=expressapp:nodejs /app/prisma ./prisma
USER expressapp
EXPOSE 3000
HEALTHCHECK --interval=30s --timeout=3s CMD wget --no-verbose --tries=1 --spider http://localhost:3000/api/health || exit 1
CMD ["node", "dist/server.js"]
```

```yaml
# docker-compose.yml
version: "3.8"

services:
  api:
    build:
      context: .
      dockerfile: Dockerfile
    ports:
      - "3000:3000"
    environment:
      NODE_ENV: production
      DATABASE_URL: postgresql://postgres:password@db:5432/myapp
      JWT_SECRET: ${JWT_SECRET}
      JWT_REFRESH_SECRET: ${JWT_REFRESH_SECRET}
    depends_on:
      db:
        condition: service_healthy
    restart: unless-stopped

  db:
    image: postgres:16-alpine
    environment:
      POSTGRES_USER: postgres
      POSTGRES_PASSWORD: password
      POSTGRES_DB: myapp
    volumes:
      - postgres_data:/var/lib/postgresql/data
    ports:
      - "5432:5432"
    healthcheck:
      test: ["CMD-SHELL", "pg_isready -U postgres"]
      interval: 5s
      timeout: 5s
      retries: 5

volumes:
  postgres_data:
```

### PM2 Process Manager

```javascript
// ecosystem.config.js
module.exports = {
  apps: [
    {
      name: "express-api",
      script: "dist/server.js",
      instances: "max",        // Use all CPU cores
      exec_mode: "cluster",    // Cluster mode for load balancing
      max_memory_restart: "500M",
      env_production: {
        NODE_ENV: "production",
      },
      log_date_format: "YYYY-MM-DD HH:mm:ss Z",
      error_file: "./logs/error.log",
      out_file: "./logs/out.log",
      merge_logs: true,
    },
  ],
};
```

```bash
# Start
pm2 start ecosystem.config.js --env production

# Monitor
pm2 monit

# Reload without downtime
pm2 reload express-api

# View logs
pm2 logs express-api
```

### Health Check Endpoint

Every production Express app should expose a health check endpoint:

```typescript
router.get("/health", async (_req, res) => {
  try {
    // Check database connectivity
    await prisma.$queryRaw`SELECT 1`;

    res.json({
      status: "healthy",
      uptime: process.uptime(),
      timestamp: new Date().toISOString(),
      version: process.env.npm_package_version,
      checks: {
        database: "connected",
        memory: process.memoryUsage(),
      },
    });
  } catch {
    res.status(503).json({
      status: "unhealthy",
      timestamp: new Date().toISOString(),
      checks: { database: "disconnected" },
    });
  }
});
```

### Graceful Shutdown

Handle process signals to cleanly close connections:

```typescript
const server = app.listen(env.PORT);

async function shutdown(signal: string) {
  console.log(`Received ${signal}. Starting graceful shutdown...`);

  server.close(async () => {
    console.log("HTTP server closed.");
    await prisma.$disconnect();
    console.log("Database disconnected. Exiting.");
    process.exit(0);
  });

  // Force exit after 10 seconds
  setTimeout(() => {
    console.error("Could not close connections in time. Forcing exit.");
    process.exit(1);
  }, 10_000);
}

process.on("SIGTERM", () => shutdown("SIGTERM"));
process.on("SIGINT", () => shutdown("SIGINT"));
```

---

## Common Patterns and Anti-Patterns

### Good Patterns

**Layered architecture:** Routes -> Controllers -> Services -> Repositories. Each layer has a single responsibility.

```
Route:       Defines the endpoint and applies middleware
Controller:  Parses request, calls service, sends response
Service:     Contains business logic, calls repositories
Repository:  Handles data access (database queries)
```

**Environment validation at startup:** Validate all required environment variables when the server starts, not when they are first used.

```typescript
// This runs at import time. If validation fails, the process exits immediately.
import { z } from "zod";
const env = z.object({ DATABASE_URL: z.string().url() }).parse(process.env);
```

**Single Prisma/Drizzle instance:** Create one database client and export it, rather than creating a new client in every file.

**Consistent error responses:** Always return the same JSON structure for errors.

**Request ID tracking:** Add a unique ID to each request for tracing through logs.

```typescript
import { randomUUID } from "node:crypto";

app.use((req, _res, next) => {
  req.id = req.headers["x-request-id"]?.toString() || randomUUID();
  next();
});
```

### Anti-Patterns to Avoid

**1. Business logic in route handlers:**

```typescript
// BAD - logic in route handler
router.post("/users", async (req, res) => {
  const existing = await prisma.user.findUnique({ where: { email: req.body.email } });
  if (existing) return res.status(409).json({ error: "Email taken" });
  const hashed = await bcrypt.hash(req.body.password, 12);
  const user = await prisma.user.create({ data: { ...req.body, password: hashed } });
  res.status(201).json(user);
});

// GOOD - delegate to service
router.post("/users", validate({ body: createUserSchema }), controller.createUser);
```

**2. Not handling errors:**

```typescript
// BAD - error is silently swallowed
try {
  await someOperation();
} catch (e) {
  // nothing here
}

// GOOD - log and forward
try {
  await someOperation();
} catch (e) {
  logger.error(e, "Operation failed");
  throw e; // Let the error handler deal with it
}
```

**3. Sending multiple responses:**

```typescript
// BAD - sends two responses, crashes
app.get("/users/:id", async (req, res) => {
  const user = await findUser(req.params.id);
  if (!user) {
    res.status(404).json({ error: "Not found" });
    // Missing return! Execution continues...
  }
  res.json(user); // Error: Cannot set headers after they are sent
});

// GOOD - return after sending
if (!user) {
  return res.status(404).json({ error: "Not found" });
}
res.json(user);
```

**4. Hardcoded configuration:**

```typescript
// BAD
const secret = "my-super-secret-key";

// GOOD
const secret = env.JWT_SECRET; // Validated at startup
```

**5. Using `app.listen()` directly for testability:**

```typescript
// BAD - cannot import app without starting the server
const app = express();
// ... setup ...
app.listen(3000);
export default app;

// GOOD - separate app creation from server start
// app.ts
export const app = express();
// server.ts
import { app } from "./app";
app.listen(env.PORT);
```

**6. Blocking the event loop:**

```typescript
// BAD - synchronous file read blocks all requests
const data = fs.readFileSync("large-file.json", "utf-8");

// GOOD - async file read
const data = await fs.promises.readFile("large-file.json", "utf-8");
```

**7. Not limiting request body size:**

```typescript
// BAD - no limit, vulnerable to large payloads
app.use(express.json());

// GOOD - explicit limit
app.use(express.json({ limit: "10kb" }));
```

**8. Returning sensitive data:**

```typescript
// BAD - returns password hash
res.json(user);

// GOOD - select specific fields or omit sensitive ones
const { password, ...safeUser } = user;
res.json(safeUser);
```

**9. Not using HTTP status codes correctly:**

```typescript
// BAD - always 200
res.json({ error: "Not found" }); // Status is 200

// GOOD - correct status code
res.status(404).json({ success: false, message: "Not found" });
```

**10. Monolithic route file:**

```typescript
// BAD - all routes in one file
app.get("/users", ...);
app.get("/users/:id", ...);
app.post("/users", ...);
app.get("/posts", ...);
app.get("/posts/:id", ...);
app.post("/comments", ...);
// ... hundreds of lines ...

// GOOD - modular routers
app.use("/api/v1/users", userRoutes);
app.use("/api/v1/posts", postRoutes);
app.use("/api/v1/comments", commentRoutes);
```

---

## Express 5 vs Express 4

Express 5 (the version used in this template) includes several important changes:

| Feature                      | Express 4            | Express 5                        |
| ---------------------------- | -------------------- | -------------------------------- |
| Async error handling         | Manual (wrap/catch)  | Automatic (rejected promises forwarded to error handler) |
| `req.query`                  | Custom parser        | Uses `URLSearchParams` by default|
| Path route matching          | `path-to-regexp` v1  | `path-to-regexp` v8 (stricter)   |
| `res.render()` callback      | Optional             | Required for async engines       |
| `app.del()`                  | Alias for `.delete()`| Removed                          |
| `req.host`                   | Included port        | Excluded port (use `req.hostname`)|
| Regex in route paths         | Supported inline     | Use named params with constraints|

The most impactful change is automatic async error handling. In Express 5, this works without any wrapper:

```typescript
router.get("/users/:id", async (req, res) => {
  const user = await userService.findById(req.params.id); // Throws if not found
  res.json({ success: true, data: user });
  // If findById rejects, Express catches the rejection and calls next(err) automatically.
});
```

---

## Further Reading

- [Express.js Official Documentation](https://expressjs.com/)
- [Express 5 Migration Guide](https://expressjs.com/en/guide/migrating-5.html)
- [Prisma Documentation](https://www.prisma.io/docs)
- [Drizzle ORM Documentation](https://orm.drizzle.team/)
- [Zod Documentation](https://zod.dev/)
- [Pino Logger](https://getpino.io/)
- [Helmet.js](https://helmetjs.github.io/)
- [OWASP Node.js Security Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Nodejs_Security_Cheat_Sheet.html)
