import { importJWK, jwtVerify } from "jose";
import type { JWTPayload, JWTVerifyOptions } from "jose";
import { ConfigKeys, getConfigValue, getNumberConfigValue } from "./config-service";
import { logger } from "../helpers/logger";
import { getClientAuthAssertion, persistClientAuthAssertion } from "./client-auth-assertion-service";
import { ClientOAuthSession } from "./client-oauth-session-service";
import { AccessTokenRequest } from "..";

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
    // TODO: PYIC-7500 Java version does not currently enforce this
    // throw new Error("Client assertion already used");
  }
  await persistClientAuthAssertion(clientAssertion.jti);
};

export const validateTokenRequest = async (
  request: AccessTokenRequest,
  clientOAuthSession: ClientOAuthSession,
): Promise<void> => {
  if (request.grant_type !== "authorization_code") {
    throw new Error(`Invalid grant type: ${request.grant_type}`);
  }
  if (!request.client_assertion) {
    throw new Error("Missing client_assertion");
  }
  if (request.client_assertion_type !== CLIENT_ASSERTION_TYPE) {
    throw new Error(`Invalid client_assertion_type: ${request.client_assertion_type}`);
  }

  const options: JWTVerifyOptions = {
    audience: await getConfigValue(ConfigKeys.componentId),
    issuer: clientOAuthSession.clientId,
    subject: clientOAuthSession.clientId,
  };

  const signingKey = await importJWK(
    JSON.parse(
      await getConfigValue(
        ConfigKeys.clientPublicSigningKey,
        clientOAuthSession.clientId)));

  const clientAssertion = (await jwtVerify(request.client_assertion, signingKey, options)).payload;

  await validateMaxExpiry(clientAssertion);
  await validateJwtId(clientAssertion);
};
