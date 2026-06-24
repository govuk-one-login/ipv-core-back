import { Logger } from "@aws-lambda-powertools/logger";
import { Context } from "aws-lambda";
import { ClientOAuthSession } from "../services/client-oauth-session-service";
import { IpvSession } from "../services/ipv-session-service";

export const logger = new Logger(); // Name captured from SAM environment variables

export const initialiseLogger = (context: Context): void => {
  if (context) {
    logger.addContext(context);
  }
};

// Append log information about the session to all log messages
export const addLogInfo = (
  ipvSession: IpvSession | undefined,
  clientOAuthSession: ClientOAuthSession | undefined,
): void => {
  logger.appendKeys({
    govuk_signin_journey_id: clientOAuthSession?.govukSigninJourneyId,
    ipvSessionId: ipvSession?.ipvSessionId,
    clientOAuthSessionId: clientOAuthSession?.clientOAuthSessionId,
    clientId: clientOAuthSession?.clientId,
  });
};
