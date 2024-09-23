import { ConfigKeys, getConfigValue, getNumberConfigValue } from "./config-service";
import { IpvSession } from "./ipv-session-service";
import { AccessTokenRequest } from "..";

export const validateAuthCode = async (request: AccessTokenRequest, ipvSession: IpvSession): Promise<void> => {
  // If the session already has an access token, then the auth code must have already been consumed.
  if (ipvSession.accessToken) {
    throw Error("Auth code already used")
  }

  // Validate the auth code has not expired
  var expiryCutoff = Date.now() - (await getNumberConfigValue(ConfigKeys.authCodeExpiry) * 1000);
  if (!ipvSession.authorizationCodeMetadata?.creationDateTime ||
    Date.parse(ipvSession.authorizationCodeMetadata?.creationDateTime) < expiryCutoff) {
    throw new Error("Auth code expired");
  }

  // Validate the redirect url matches the one linked to the auth code
  if (!ipvSession.authorizationCodeMetadata.redirectUrl ||
    request.redirect_uri !== ipvSession.authorizationCodeMetadata.redirectUrl) {
    throw new Error("Incorrect redirect URL")
  }
};
