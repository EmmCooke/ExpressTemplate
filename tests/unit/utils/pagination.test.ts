import { describe, it, expect } from "vitest";
import { buildPaginationMeta } from "../../../src/utils/pagination";

describe("buildPaginationMeta", () => {
  it("should calculate pagination correctly", () => {
    const meta = buildPaginationMeta(100, 1, 20);
    expect(meta.totalPages).toBe(5);
    expect(meta.hasNext).toBe(true);
    expect(meta.hasPrev).toBe(false);
  });

  it("should detect last page", () => {
    const meta = buildPaginationMeta(100, 5, 20);
    expect(meta.hasNext).toBe(false);
    expect(meta.hasPrev).toBe(true);
  });
});
