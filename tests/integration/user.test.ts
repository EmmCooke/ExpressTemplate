import { describe, it, expect } from "vitest";
import request from "supertest";
import { app } from "../../src/app";

describe("GET /api/v1/users", () => {
  it("should return 401 without token", async () => {
    const res = await request(app).get("/api/v1/users");
    expect(res.status).toBe(401);
  });
});
