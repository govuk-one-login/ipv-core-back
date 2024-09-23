import { DynamoDBClient } from "@aws-sdk/client-dynamodb";
import { DynamoDBDocument } from "@aws-sdk/lib-dynamodb";
import { sha256 } from "../helpers/hash-helper";
import { logger } from "../helpers/logger";

const TABLE_NAME = process.env.IPV_SESSIONS_TABLE_NAME || 'ipv-session-table';

const MAX_ATTEMPTS = 5;
const BASE_BACKOFF_MILLIS = 50;

const dynamoClient = DynamoDBDocument.from(
  new DynamoDBClient({ region: "eu-west-2" }));

// Incomplete type for now
export type IpvSessionItem = {
  ipvSessionId: string;
  clientOAuthSessionId: string;
  criOAuthSessionId?: string;
  creationDateTime: string;
  authorizationCode?: string;
  authorizationCodeMetadata?: {
    creationDateTime: string;
    redirectUrl: string;
  };
  accessToken?: string;
  accessTokenMetadata?: {
    creationDateTime: string;
    expiryDateTime: string;
    revokedAtDateTime?: string;
  };
  errorCode?: string;
  errorDescription?: string;
  vot?: string;
  targetVot?: string;
  emailAddress?: string;
  reverificationStatus?: string;
  stateStack: string[];
};

const getIpvSessionByAuthCodeInternal = async (authCode: string): Promise<IpvSessionItem | null> => {
  const queryResult = await dynamoClient.query({
    TableName: TABLE_NAME,
    IndexName: 'authorizationCode',
    KeyConditionExpression: 'authorizationCode = :a',
    ExpressionAttributeValues: {
      ':a': sha256(authCode),
    },
  });

  if (!queryResult.Items?.length) {
    return null;
  }

  logger.info("Found session", { session: queryResult.Items[0] });
  return queryResult.Items[0] as IpvSessionItem;
};

const wait = async (millis: number): Promise<void> => {
  return new Promise((resolve) => setTimeout(resolve, millis));
};

export const getIpvSessionByAuthCode = async (authCode: string): Promise<IpvSessionItem> => {
  for (let attempt = 1; attempt <= MAX_ATTEMPTS; attempt++) {
    const result = await getIpvSessionByAuthCodeInternal(authCode);

    if (result) {
      return result;
    }

    if (attempt < MAX_ATTEMPTS) {
      logger.info("No session found, retrying...");
      await wait(BASE_BACKOFF_MILLIS * Math.pow(2, attempt - 1));
    }
  }
  throw new Error('No IPV Session found for auth code');
};

export const updateIpvSession = async (ipvSession: IpvSessionItem): Promise<void> => {
  await dynamoClient.put({
    TableName: TABLE_NAME,
    Item: ipvSession,
  });
};
