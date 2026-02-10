import { describe, it, expect } from "vitest";
import request from "supertest";
import { app } from "../../src/app";

describe("POST /api/v1/auth/register", () => {
  it("should return 400 for invalid email", async () => {
    const res = await request(app)
      .post("/api/v1/auth/register")
      .send({ email: "invalid", password: "Password1", name: "Test" });

    expect(res.status).toBe(400);
    expect(res.body.success).toBe(false);
  });
});

describe("POST /api/v1/auth/login", () => {
  it("should return 401 for wrong credentials", async () => {
    const res = await request(app)
      .post("/api/v1/auth/login")
      .send({ email: "nobody@example.com", password: "Wrong1234" });

    expect(res.status).toBe(401);
  });
});
