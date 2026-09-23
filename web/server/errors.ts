export class GatewayError extends Error {
  constructor(
    public status: number,
    public code: string,
    message: string,
    public details?: string,
    public requestId?: string,
    public retryAfter?: string,
  ) {
    super(message);
  }
}
