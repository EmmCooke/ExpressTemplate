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
