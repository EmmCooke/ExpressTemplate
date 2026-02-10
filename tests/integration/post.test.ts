import { describe, it, expect } from "vitest";
import request from "supertest";
import { app } from "../../src/app";

describe("GET /api/v1/posts", () => {
  it("should return 200 for public post listing", async () => {
    const res = await request(app).get("/api/v1/posts");
    expect(res.status).toBe(200);
    expect(res.body.success).toBe(true);
  });
});
