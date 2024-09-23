import { APIGatewayProxyHandlerV2, APIGatewayProxyEventV2 } from "aws-lambda";
import { AccessTokenResponse, generateAccessTokenResponse } from "./services/access-token-service";
import { getIpvSessionByAuthCode, IpvSession, updateIpvSession } from "./services/ipv-session-service";
import { validateTokenRequest } from "./services/token-request-validator";
import { validateAuthCode } from "./services/auth-code-validator";
import { sha256 } from "./helpers/hash-helper";
import { ConfigKeys, getNumberConfigValue } from "./services/config-service";
import { addLogInfo, initialiseLogger, logger } from "./helpers/logger";
import { getClientOauthSession } from "./services/client-oauth-session-service";
import { proxyApiResponse } from "./helpers/response-helper";

export type AccessTokenRequest = {
  grant_type: string;
  code: string;
  redirect_uri: string;
  client_assertion?: string; // JWT
  client_assertion_type?: string;
};

const parseBody = (request: APIGatewayProxyEventV2): AccessTokenRequest => {
  const searchParams = new URLSearchParams(request.body);
  const res: Record<string, string> = {};
  for (const [key, value] of searchParams.entries()) {
    res[key] = value;
  }
  return res as AccessTokenRequest;
};

const updateSessionWithAccessToken = async (ipvSession: IpvSession, accessToken: string): Promise<void> => {
  ipvSession.accessToken = sha256(accessToken);
  ipvSession.accessTokenMetadata = {
    creationDateTime: new Date().toISOString(),
    expiryDateTime: new Date(Date.now() + (await getNumberConfigValue(ConfigKeys.authCodeExpiry) * 1000)).toISOString(),
  }
  updateIpvSession(ipvSession);
};

export const handler: APIGatewayProxyHandlerV2<AccessTokenResponse> = async (event, context) => {
  try {
    // Initialise
    initialiseLogger(context);
    const request = parseBody(event);
    const ipvSession = await getIpvSessionByAuthCode(request.code);
    const clientOauthSession = await getClientOauthSession(ipvSession.clientOAuthSessionId);
    addLogInfo(ipvSession, clientOauthSession);

    // Validate request
    await validateTokenRequest(request, clientOauthSession);
    await validateAuthCode(request, ipvSession);

    // Generate access token
    const accessTokenResponse = await generateAccessTokenResponse();
    await updateSessionWithAccessToken(ipvSession, accessTokenResponse.access_token);

    logger.info("Successfully generated IPV client access token");

    return proxyApiResponse(accessTokenResponse);
  } catch (error: unknown) {
    // TODO: proper error handling
    logger.error("Something went wrong", { error: error });
    return proxyApiResponse({
      error: "server_error",
      error_description: "Unexpected server error",
    }, 500);
  }
};
