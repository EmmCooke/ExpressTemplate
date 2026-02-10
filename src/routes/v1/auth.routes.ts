import { Router } from "express";
import { AuthController } from "../../controllers/auth.controller";
import { validate } from "../../middleware/validate";
import { loginSchema, registerSchema } from "../../validators/auth.validator";
import { authLimiter } from "../../middleware/rateLimiter";

const router = Router();
const controller = new AuthController();

router.use(authLimiter);
router.post("/login", validate({ body: loginSchema }), controller.login);
router.post("/register", validate({ body: registerSchema }), controller.register);

export { router as authRoutes };
