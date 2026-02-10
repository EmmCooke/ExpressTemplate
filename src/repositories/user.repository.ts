import { prisma } from "../config/database.js";
import { ApiError } from "../utils/ApiError.js";

export class UserRepository {
  async findAll(params: { page: number; limit: number }) {
    const skip = (params.page - 1) * params.limit;
    const [users, total] = await Promise.all([
      prisma.user.findMany({
        skip,
        take: params.limit,
        select: { id: true, email: true, name: true, role: true, createdAt: true },
        orderBy: { createdAt: "desc" },
      }),
      prisma.user.count(),
    ]);
    return { data: users, total, page: params.page, limit: params.limit };
  }

  async findById(id: string) {
    const user = await prisma.user.findUnique({ where: { id } });
    if (!user) throw ApiError.notFound(`User with ID ${id} not found`);
    return user;
  }

  async findByEmail(email: string) {
    return prisma.user.findUnique({ where: { email } });
  }

  async create(data: { email: string; password: string; name: string }) {
    return prisma.user.create({ data });
  }

  async update(id: string, data: Partial<{ email: string; name: string }>) {
    return prisma.user.update({ where: { id }, data });
  }

  async delete(id: string) {
    await prisma.user.delete({ where: { id } });
  }
}
