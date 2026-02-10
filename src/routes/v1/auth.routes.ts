import { Router } from "express";
import { AuthController } from "../../controllers/auth.controller.js";
import { validate } from "../../middleware/validate.js";
import { loginSchema, registerSchema } from "../../validators/auth.validator.js";
import { authLimiter } from "../../middleware/rateLimiter.js";

const router = Router();
const controller = new AuthController();

router.use(authLimiter);
router.post("/login", validate({ body: loginSchema }), controller.login);
router.post("/register", validate({ body: registerSchema }), controller.register);

export { router as authRoutes };
