import { Request, Response } from "express";
import { PostService } from "../services/post.service";
import { asyncHandler } from "../utils/asyncHandler";

const postService = new PostService();

export class PostController {
  getPosts = asyncHandler(async (req: Request, res: Response) => {
    const { page, limit } = req.query as { page?: string; limit?: string };
    const result = await postService.findAll({
      page: Number(page) || 1,
      limit: Number(limit) || 20,
    });
    res.json({ success: true, data: result });
  });

  getPostById = asyncHandler(async (req: Request, res: Response) => {
    const post = await postService.findById(req.params.id);
    res.json({ success: true, data: post });
  });

  createPost = asyncHandler(async (req: Request, res: Response) => {
    const post = await postService.create(req.body);
    res.status(201).json({ success: true, data: post });
  });

  updatePost = asyncHandler(async (req: Request, res: Response) => {
    const post = await postService.update(req.params.id, req.body);
    res.json({ success: true, data: post });
  });

  deletePost = asyncHandler(async (req: Request, res: Response) => {
    await postService.delete(req.params.id);
    res.status(204).send();
  });
}
