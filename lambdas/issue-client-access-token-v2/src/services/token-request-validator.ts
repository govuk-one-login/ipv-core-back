import { importJWK, jwtVerify } from "jose";
import type { JWTPayload, JWTVerifyOptions } from "jose";
import { ConfigKeys, getConfigValue, getNumberConfigValue } from "./config-service";
import { logger } from "../helpers/logger";
import { getClientAuthAssertion, persistClientAuthAssertion } from "./client-auth-assertion-service";

export type AccessTokenRequest = {
  grant_type: string;
  code: string;
  redirect_uri: string;
  client_assertion?: string; // JWT
  client_assertion_type?: string;
};

const CLIENT_ASSERTION_TYPE = "urn:ietf:params:oauth:client-assertion-type:jwt-bearer";

const validateMaxExpiry = async (clientAssertion: JWTPayload): Promise<void> => {
  var maxTtl = await getNumberConfigValue(ConfigKeys.maxClientAuthTtl);
  if (!clientAssertion.exp || clientAssertion.exp > Date.now() + maxTtl) {
    throw new Error("Invalid client assertion expiry");
  }
};

const validateJwtId = async (clientAssertion: JWTPayload): Promise<void> => {
  if (!clientAssertion.jti) {
    throw new Error("Invalid client assertion JTI");
  }
  const previousClientAuthAssertion = await getClientAuthAssertion(clientAssertion.jti);
  if (previousClientAuthAssertion) {
    logger.error("Client assertion already used", {
      jti: previousClientAuthAssertion.jwtId,
      usedAt: previousClientAuthAssertion.usedAtDateTime,
    });
    // TODO: Java version does not currently validate this
    // throw new Error("Client assertion already used");
  }
  await persistClientAuthAssertion(clientAssertion.jti);
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

  logger.info("token_request", request);

  // TODO: should we verify anything else here - client id?
  // iss and sub are both client id
  // the other side should probably come from the clientoauthsession
  const options: JWTVerifyOptions = {
    audience: await getConfigValue(ConfigKeys.componentId),
  };

  const signingKey = await importJWK(
    JSON.parse(
      await getConfigValue(
        ConfigKeys.clientPublicSigningKey,
        "orchestrator")));

  const clientAssertion = (await jwtVerify(request.client_assertion, signingKey, options)).payload;

  await validateMaxExpiry(clientAssertion);
  await validateJwtId(clientAssertion);
};
