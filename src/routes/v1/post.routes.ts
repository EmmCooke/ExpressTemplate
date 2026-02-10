import { Router } from "express";
import { PostController } from "../../controllers/post.controller.js";
import { authenticate } from "../../middleware/authenticate.js";
import { validate } from "../../middleware/validate.js";
import { createPostSchema, updatePostSchema } from "../../validators/post.validator.js";
import { paginationSchema } from "../../validators/common.validator.js";

const router = Router();
const controller = new PostController();

router.get("/", validate({ query: paginationSchema }), controller.getPosts);
router.get("/:id", controller.getPostById);
router.post("/", authenticate, validate({ body: createPostSchema }), controller.createPost);
router.put("/:id", authenticate, validate({ body: updatePostSchema }), controller.updatePost);
router.delete("/:id", authenticate, controller.deletePost);

export { router as postRoutes };
