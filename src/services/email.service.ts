import { logger } from "../config/logger.js";

export class EmailService {
  async sendWelcomeEmail(to: string, name: string): Promise<void> {
    // Replace with real email provider (SendGrid, Resend, etc.)
    logger.info({ to, name }, "Sending welcome email");
  }

  async sendPasswordResetEmail(to: string, _resetToken: string): Promise<void> {
    logger.info({ to, resetToken: "***" }, "Sending password reset email");
  }
}
