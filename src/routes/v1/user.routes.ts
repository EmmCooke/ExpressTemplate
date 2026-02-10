import { Router } from "express";
import { UserController } from "../../controllers/user.controller.js";
import { authenticate } from "../../middleware/authenticate.js";
import { authorize } from "../../middleware/authorize.js";
import { validate } from "../../middleware/validate.js";
import { createUserSchema, updateUserSchema } from "../../validators/user.validator.js";
import { paginationSchema } from "../../validators/common.validator.js";

const router = Router();
const controller = new UserController();

router.get("/", authenticate, validate({ query: paginationSchema }), controller.getUsers);
router.get("/:id", authenticate, controller.getUserById);
router.post(
  "/",
  authenticate,
  authorize("admin"),
  validate({ body: createUserSchema }),
  controller.createUser,
);
router.put(
  "/:id",
  authenticate,
  authorize("admin"),
  validate({ body: updateUserSchema }),
  controller.updateUser,
);
router.delete("/:id", authenticate, authorize("admin"), controller.deleteUser);

export { router as userRoutes };
