import { Router } from "express";
import { PostController } from "../../controllers/post.controller";
import { authenticate } from "../../middleware/authenticate";
import { validate } from "../../middleware/validate";
import { createPostSchema, updatePostSchema } from "../../validators/post.validator";
import { paginationSchema } from "../../validators/common.validator";

const router = Router();
const controller = new PostController();

router.get("/", validate({ query: paginationSchema }), controller.getPosts);
router.get("/:id", controller.getPostById);
router.post("/", authenticate, validate({ body: createPostSchema }), controller.createPost);
router.put("/:id", authenticate, validate({ body: updatePostSchema }), controller.updatePost);
router.delete("/:id", authenticate, controller.deletePost);

export { router as postRoutes };
