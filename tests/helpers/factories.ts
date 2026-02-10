export function buildUser(overrides: Record<string, unknown> = {}) {
  return {
    id: "test-user-id",
    email: "test@example.com",
    name: "Test User",
    role: "user",
    password: "$2a$12$hashed",
    createdAt: new Date(),
    updatedAt: new Date(),
    ...overrides,
  };
}

export function buildPost(overrides: Record<string, unknown> = {}) {
  return {
    id: "test-post-id",
    title: "Test Post",
    content: "Test content",
    authorId: "test-user-id",
    createdAt: new Date(),
    updatedAt: new Date(),
    ...overrides,
  };
}
