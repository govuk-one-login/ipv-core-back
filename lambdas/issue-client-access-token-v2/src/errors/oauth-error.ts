type OAuthErrorObject = {
  errorCode: string;
  errorDescription: string;
  statusCode: number;
};

export const OAuthErrors = {
  InvalidAuthCode: {
    errorCode: "invalid_grant",
    errorDescription: "Invalid authorization code",
    statusCode: 400
  },
  InvalidGrant: {
    errorCode: "invalid_grant",
    errorDescription: "Invalid grant",
    statusCode: 400
  },
  InvalidClient: {
    errorCode: "invalid_client",
    errorDescription: "Client authentication failed",
    statusCode: 401,
  },
  ServerError: {
    errorCode: "server_error",
    errorDescription: "Unexpected server error",
    statusCode: 500,
  },
} satisfies Record<string, OAuthErrorObject>;

export class OAuthError extends Error {
  oAuthError: OAuthErrorObject;

  constructor(error: OAuthErrorObject, message?: string) {
    super(message ?? error.errorDescription);
    this.oAuthError = error;
    Error.captureStackTrace(this, this.constructor);
  }
}
