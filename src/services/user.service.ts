import { UserRepository } from "../repositories/user.repository";

const userRepo = new UserRepository();

export class UserService {
  async findAll(params: { page: number; limit: number }) {
    return userRepo.findAll(params);
  }

  async findById(id: string) {
    return userRepo.findById(id);
  }

  async create(data: { email: string; password: string; name: string }) {
    return userRepo.create(data);
  }

  async update(id: string, data: Partial<{ email: string; name: string }>) {
    return userRepo.update(id, data);
  }

  async delete(id: string) {
    return userRepo.delete(id);
  }
}
