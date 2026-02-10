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
