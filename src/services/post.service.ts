import { PostRepository } from "../repositories/post.repository.js";

const postRepo = new PostRepository();

export class PostService {
  async findAll(params: { page: number; limit: number }) {
    return postRepo.findAll(params);
  }

  async findById(id: string) {
    return postRepo.findById(id);
  }

  async create(data: { title: string; content: string; authorId: string }) {
    return postRepo.create(data);
  }

  async update(id: string, data: Partial<{ title: string; content: string }>) {
    return postRepo.update(id, data);
  }

  async delete(id: string) {
    return postRepo.delete(id);
  }
}
