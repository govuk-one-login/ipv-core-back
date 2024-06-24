import { APIGatewayProxyHandlerV2, APIGatewayProxyEventV2 } from "aws-lambda";
import { AccessTokenResponse, generateAccessTokenResponse } from "./services/access-token-service";
import { getIpvSessionByAuthCode, updateIpvSession } from "./services/ipv-session-service";
import { AccessTokenRequest, validateTokenRequest } from "./services/token-request-validator";
import { validateAuthCode } from "./services/auth-code-validator";
import { sha256 } from "./helpers/hash-helper";

// From config
const ACCESS_TOKEN_TTL = 300;

const parseBody = (request: APIGatewayProxyEventV2): AccessTokenRequest => {
  const searchParams = new URLSearchParams(request.body);
  const res: Record<string, string> = {};
  for (const [key, value] of searchParams.entries()) {
    res[key] = value;
  }
  return res as AccessTokenRequest;
};

export const handler: APIGatewayProxyHandlerV2<AccessTokenResponse> = async (event) => {
  const request = parseBody(event);
  await validateTokenRequest(request);

  // Also need client oauth session for logs/audit (to get the govuk_signin_journeyid)
  const ipvSession = await getIpvSessionByAuthCode(request.code);
  validateAuthCode(request, ipvSession);

  const accessTokenResponse = generateAccessTokenResponse();

  // TODO: In integration only, log a SHA of the token

  ipvSession.accessToken = sha256(accessTokenResponse.access_token);
  ipvSession.accessTokenMetadata = {
    creationDateTime: new Date().toUTCString(),
    expiryDateTime: new Date(Date.now() + ACCESS_TOKEN_TTL).toUTCString(),
  }
  updateIpvSession(ipvSession);

  return accessTokenResponse;
};
