import { DynamoDBClient } from "@aws-sdk/client-dynamodb";
import { DynamoDBDocument } from "@aws-sdk/lib-dynamodb";
import AWSXRay from "aws-xray-sdk";
import { sha256 } from "../helpers/hash-helper";
import { logger } from "../helpers/logger";
import { retryOptionalTask } from "../helpers/retry-helper";

const TABLE_NAME = process.env.IPV_SESSIONS_TABLE_NAME || 'ipv-session-table';

const dynamoClient = DynamoDBDocument.from(
  AWSXRay.captureAWSv3Client(
    new DynamoDBClient({ region: "eu-west-2" })));

export type IpvSession = {
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

const getIpvSessionByAuthCodeInternal = async (authCode: string): Promise<IpvSession | undefined> => {
  const queryResult = await dynamoClient.query({
    TableName: TABLE_NAME,
    IndexName: 'authorizationCode',
    KeyConditionExpression: 'authorizationCode = :a',
    ExpressionAttributeValues: {
      ':a': sha256(authCode),
    },
  });

  if (!queryResult.Items?.length) {
    return undefined;
  }

  return queryResult.Items[0] as IpvSession;
};


export const getIpvSessionByAuthCode = (authCode: string): Promise<IpvSession | undefined> => {
  return retryOptionalTask(() => getIpvSessionByAuthCodeInternal(authCode));
};

export const updateIpvSession = async (ipvSession: IpvSession): Promise<void> => {
  await dynamoClient.put({
    TableName: TABLE_NAME,
    Item: ipvSession,
  });
};
