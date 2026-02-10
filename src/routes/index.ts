import { Router } from "express";
import { v1Routes } from "./v1";

const router = Router();

router.get("/health", (_req, res) => {
  res.json({ status: "ok", uptime: process.uptime(), timestamp: new Date().toISOString() });
});

router.use("/v1", v1Routes);

export { router as routes };
