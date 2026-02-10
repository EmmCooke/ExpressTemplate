export interface PaginatedResult<T> {
  data: T[];
  total: number;
  page: number;
  limit: number;
}

export interface ServiceResponse<T> {
  success: boolean;
  data?: T;
  message?: string;
}
