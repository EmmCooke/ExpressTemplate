import { prisma } from "../config/database";
import { ApiError } from "../utils/ApiError";

export class PostRepository {
  async findAll(params: { page: number; limit: number }) {
    const skip = (params.page - 1) * params.limit;
    const [posts, total] = await Promise.all([
      prisma.post.findMany({
        skip,
        take: params.limit,
        include: { author: { select: { id: true, name: true } } },
        orderBy: { createdAt: "desc" },
      }),
      prisma.post.count(),
    ]);
    return { data: posts, total, page: params.page, limit: params.limit };
  }

  async findById(id: string) {
    const post = await prisma.post.findUnique({
      where: { id },
      include: { author: { select: { id: true, name: true } } },
    });
    if (!post) throw ApiError.notFound(`Post with ID ${id} not found`);
    return post;
  }

  async create(data: { title: string; content: string; authorId: string }) {
    return prisma.post.create({ data });
  }

  async update(id: string, data: Partial<{ title: string; content: string }>) {
    return prisma.post.update({ where: { id }, data });
  }

  async delete(id: string) {
    await prisma.post.delete({ where: { id } });
  }
}
