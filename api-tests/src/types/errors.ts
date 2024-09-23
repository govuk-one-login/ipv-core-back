export class ApiRequestError extends Error {
  statusCode: number;
  statusText?: string;
  origin: string;

  constructor(
    statusCode: number,
    origin: string,
    statusText?: string,
    message?: string,
  ) {
    super();
    this.statusCode = statusCode;
    this.origin = origin;
    this.statusText = statusText;
    this.message = message ?? "";
  }
}
