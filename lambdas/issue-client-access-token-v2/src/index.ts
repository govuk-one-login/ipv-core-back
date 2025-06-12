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
import { OAuthError, OAuthErrors } from "./errors/oauth-error";

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
    const clientOauthSession = ipvSession && await getClientOauthSession(ipvSession?.clientOAuthSessionId);
    addLogInfo(ipvSession, clientOauthSession);

    // Validate request
    if (!ipvSession || !clientOauthSession) {
      throw new OAuthError(OAuthErrors.InvalidAuthCode, "No IPV session found for auth code");
    }
    await validateTokenRequest(request, clientOauthSession);
    await validateAuthCode(request, ipvSession);

    // Generate access token
    const accessTokenResponse = await generateAccessTokenResponse();
    await updateSessionWithAccessToken(ipvSession, accessTokenResponse.access_token);

    logger.info("Successfully generated IPV client access token");

    return proxyApiResponse(accessTokenResponse);
  } catch (error: unknown) {
    const oAuthError = error instanceof OAuthError
      ? error.oAuthError
      : OAuthErrors.ServerError;

    const errorResponse = {
      error: oAuthError.errorCode,
      error_description: oAuthError.errorDescription,
    };

    logger.error(`Returning ${errorResponse.error} error`, {
      error: {
        ...oAuthError,
        message: (error as Error)?.message,
        stack: (error as Error)?.stack,
      },
    });

    return proxyApiResponse(errorResponse, oAuthError.statusCode);
  }
};
