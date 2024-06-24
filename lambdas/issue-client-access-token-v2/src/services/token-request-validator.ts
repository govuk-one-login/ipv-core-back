import { jwtVerify } from "jose";
import type { JWTPayload, JWTVerifyOptions, KeyLike } from "jose";

export type AccessTokenRequest = {
  grant_type: string;
  code: string;
  redirect_uri: string;
  code_verifier?: string;
  client_id?: string;
  client_assertion?: string; // JWT
  client_assertion_type?: string;
};

const CLIENT_ASSERTION_TYPE = "urn:ietf:params:oauth:client-assertion-type:jwt-bearer";
const MAX_TTL = 300;

// TODO: get key from config
const key: KeyLike = null;

const validateMaxExpiry = (clientAssertion: JWTPayload): void => {
  if (!clientAssertion.exp || clientAssertion.exp > Date.now() + MAX_TTL) {
    throw new Error("Invalid client assertion expiry");
  }
};

const validateJwtId = (clientAssertion: JWTPayload): void => {
  if (!clientAssertion.jti) {
    // TODO: read from table to prevent replay attacks!
    throw new Error("Invalid client assertion JTI");
  }
};

export const validateTokenRequest = async (request: AccessTokenRequest): Promise<void> => {
  if (request.grant_type !== "authorization_code") {
    throw new Error(`Invalid grant type: ${request.grant_type}`);
  }
  if (!request.client_assertion) {
    throw new Error("Missing client_assertion");
  }
  if (request.client_assertion_type !== CLIENT_ASSERTION_TYPE) {
    throw new Error(`Invalid client_assertion_type: ${request.client_assertion_type}`);
  }

  // QQ what needs checking here? In Java the client id is checked, but should also check the audience, sub etc.?
  const options: JWTVerifyOptions = {

  };

  const clientAssertion = (await jwtVerify(request.client_assertion, key, options)).payload;
  validateMaxExpiry(clientAssertion);
  validateJwtId(clientAssertion);
};
