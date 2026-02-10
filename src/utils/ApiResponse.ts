export function successResponse<T>(data: T, meta?: Record<string, unknown>) {
  return { success: true as const, data, ...(meta && { meta }) };
}

export function errorResponse(message: string, errors?: Record<string, string>[]) {
  return { success: false as const, message, ...(errors && { errors }) };
}
