import { describe, it, expect, vi, beforeEach } from "vitest";
import { UserService } from "../../../src/services/user.service";

vi.mock("../../../src/repositories/user.repository", () => {
  const mockRepo = {
    findAll: vi.fn(),
    findById: vi.fn(),
    create: vi.fn(),
    update: vi.fn(),
    delete: vi.fn(),
  };
  return { UserRepository: vi.fn(() => mockRepo) };
});

import { UserRepository } from "../../../src/repositories/user.repository";

const mockRepo = new UserRepository() as unknown as Record<string, ReturnType<typeof vi.fn>>;

describe("UserService", () => {
  let service: UserService;

  beforeEach(() => {
    vi.clearAllMocks();
    service = new UserService();
  });

  describe("findAll", () => {
    it("should delegate to UserRepository.findAll with pagination params", async () => {
      const params = { page: 1, limit: 10 };
      const expected = { data: [], total: 0 };
      mockRepo.findAll.mockResolvedValue(expected);

      const result = await service.findAll(params);

      expect(mockRepo.findAll).toHaveBeenCalledWith(params);
      expect(result).toEqual(expected);
    });
  });

  describe("findById", () => {
    it("should delegate to UserRepository.findById", async () => {
      const user = { id: "abc-123", email: "test@example.com", name: "Test User" };
      mockRepo.findById.mockResolvedValue(user);

      const result = await service.findById("abc-123");

      expect(mockRepo.findById).toHaveBeenCalledWith("abc-123");
      expect(result).toEqual(user);
    });
  });

  describe("create", () => {
    it("should delegate to UserRepository.create with user data", async () => {
      const data = { email: "new@example.com", password: "hashed", name: "New User" };
      const created = { id: "def-456", ...data };
      mockRepo.create.mockResolvedValue(created);

      const result = await service.create(data);

      expect(mockRepo.create).toHaveBeenCalledWith(data);
      expect(result).toEqual(created);
    });
  });

  describe("delete", () => {
    it("should delegate to UserRepository.delete", async () => {
      mockRepo.delete.mockResolvedValue(undefined);

      await service.delete("abc-123");

      expect(mockRepo.delete).toHaveBeenCalledWith("abc-123");
    });
  });
});
