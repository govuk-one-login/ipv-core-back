import { DynamoDBClient } from "@aws-sdk/client-dynamodb";
import { DynamoDBDocument } from "@aws-sdk/lib-dynamodb";
import AWSXRay from "aws-xray-sdk";

const TABLE_NAME = process.env.CLIENT_OAUTH_SESSIONS_TABLE_NAME || 'ipv-client-oauth-session-table';

const dynamoClient = DynamoDBDocument.from(
  AWSXRay.captureAWSv3Client(
    new DynamoDBClient({ region: "eu-west-2" })));

export type ClientOAuthSession = {
  clientOAuthSessionId: string;
  responseType: string;
  clientId: string;
  scope: string;
  redirectUri: string;
  state: string;
  userId: string;
  govukSigninJourneyId: string;
  reproveIdentity: boolean;
  vtr?: string[];
  ttl: number;
  evcsAccessToken: string;
};

export const getClientOauthSession = async (clientOAuthSessionId: string): Promise<ClientOAuthSession> => {
  const result = await dynamoClient.get({
    TableName: TABLE_NAME,
    Key: { clientOAuthSessionId }
  });

  if (!result.Item) {
    throw new Error("Could not find client OAuth session");
  }

  return result.Item as ClientOAuthSession;
};
