import { APIGatewayProxyHandlerV2, APIGatewayProxyEventV2 } from "aws-lambda";
import { AccessTokenResponse, generateAccessTokenResponse } from "./services/access-token-service";
import { getIpvSessionByAuthCode, IpvSessionItem, updateIpvSession } from "./services/ipv-session-service";
import { AccessTokenRequest, validateTokenRequest } from "./services/token-request-validator";
import { validateAuthCode } from "./services/auth-code-validator";
import { sha256 } from "./helpers/hash-helper";
import { ConfigKeys, getNumberConfigValue } from "./services/config-service";
import { initialiseLogger, logger } from "./helpers/logger";

const parseBody = (request: APIGatewayProxyEventV2): AccessTokenRequest => {
  const searchParams = new URLSearchParams(request.body);
  const res: Record<string, string> = {};
  for (const [key, value] of searchParams.entries()) {
    res[key] = value;
  }
  return res as AccessTokenRequest;
};

const updateSessionWithAccessToken = async (ipvSession: IpvSessionItem, accessToken: string): Promise<void> => {
  ipvSession.accessToken = sha256(accessToken);
  ipvSession.accessTokenMetadata = {
    creationDateTime: new Date().toISOString(),
    expiryDateTime: new Date(Date.now() + (await getNumberConfigValue(ConfigKeys.authCodeExpiry) * 1000)).toISOString(),
  }
  updateIpvSession(ipvSession);
};

export const handler: APIGatewayProxyHandlerV2<AccessTokenResponse> = async (event, context) => {
  try {
    initialiseLogger(context);

    const request = parseBody(event);
    await validateTokenRequest(request);

    // Also need client oauth session for logs/audit (to get the govuk_signin_journeyid)
    const ipvSession = await getIpvSessionByAuthCode(request.code);
    await validateAuthCode(request, ipvSession);

    const accessTokenResponse = await generateAccessTokenResponse();
    await updateSessionWithAccessToken(ipvSession, accessTokenResponse.access_token);

    logger.info("Successfully generated IPV client access token");

    return {
      statusCode: 200,
      body: JSON.stringify(accessTokenResponse),
      headers: {
        "content-type": "application/json",
      },
      isBase64Encoded: false,
    };
  } catch (error: unknown) {
    // TODO: proper error handling
    logger.error("Something went wrong", { error: error });
    return {
      statusCode: 500,
      body: JSON.stringify({
        error: "server_error",
        error_description: "Unexpected server error",
      }),
      headers: {
        "content-type": "application/json",
      },
      isBase64Encoded: false,
    };
  }
};
