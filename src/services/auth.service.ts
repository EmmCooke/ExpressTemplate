import jwt, { type SignOptions } from "jsonwebtoken";
import bcrypt from "bcryptjs";
import { env } from "../config/env.js";
import { UserRepository } from "../repositories/user.repository.js";
import { ApiError } from "../utils/ApiError.js";

const userRepo = new UserRepository();

export class AuthService {
  async login(email: string, password: string) {
    const user = await userRepo.findByEmail(email);
    if (!user || !(await bcrypt.compare(password, user.password))) {
      throw ApiError.unauthorized("Invalid email or password");
    }

    const accessTokenOpts: SignOptions = { expiresIn: env.JWT_EXPIRES_IN as SignOptions["expiresIn"] };
    const accessToken = jwt.sign({ userId: user.id, role: user.role }, env.JWT_SECRET, accessTokenOpts);

    const refreshTokenOpts: SignOptions = { expiresIn: "7d" as SignOptions["expiresIn"] };
    const refreshToken = jwt.sign({ userId: user.id }, env.JWT_REFRESH_SECRET, refreshTokenOpts);

    return {
      accessToken,
      refreshToken,
      user: { id: user.id, email: user.email, role: user.role },
    };
  }

  async register(data: { email: string; password: string; name: string }) {
    const existing = await userRepo.findByEmail(data.email);
    if (existing) throw ApiError.conflict("Email already registered");

    const hashedPassword = await bcrypt.hash(data.password, 12);
    const user = await userRepo.create({ ...data, password: hashedPassword });
    return { id: user.id, email: user.email, name: user.name };
  }
}
