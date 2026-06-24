import { ConfigKeys, getNumberConfigValue } from "./config-service";
import { IpvSession } from "./ipv-session-service";
import { AccessTokenRequest } from "..";
import { OAuthError, OAuthErrors } from "../errors/oauth-error";

export const validateAuthCode = async (request: AccessTokenRequest, ipvSession: IpvSession): Promise<void> => {
  // If the session already has an access token, then the auth code must have already been consumed.
  if (ipvSession.accessToken) {
    throw new OAuthError(OAuthErrors.InvalidAuthCode, "Auth code has already been used");
  }

  // Validate the auth code has not expired
  var expiryCutoff = Date.now() - (await getNumberConfigValue(ConfigKeys.authCodeExpiry) * 1000);
  if (!ipvSession.authorizationCodeMetadata?.creationDateTime ||
    Date.parse(ipvSession.authorizationCodeMetadata?.creationDateTime) < expiryCutoff) {
      throw new OAuthError(OAuthErrors.InvalidAuthCode, "Auth code expired");
  }

  // Validate the redirect url matches the one linked to the auth code
  if (!ipvSession.authorizationCodeMetadata.redirectUrl ||
    request.redirect_uri !== ipvSession.authorizationCodeMetadata.redirectUrl) {
      throw new OAuthError(OAuthErrors.InvalidAuthCode, "Invalid redirect URL");
  }
};
