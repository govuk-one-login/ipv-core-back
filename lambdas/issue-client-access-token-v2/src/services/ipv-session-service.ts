import { DynamoDBClient } from "@aws-sdk/client-dynamodb";
import { DynamoDBDocument } from "@aws-sdk/lib-dynamodb";
import { unmarshall } from "@aws-sdk/util-dynamodb";

const TABLE_NAME = 'ipv-session-table';

const dynamoClient = DynamoDBDocument.from(
  new DynamoDBClient({ region: "eu-west-2" }));

// incomplete type
export type IpvSessionItem = {
  ipvSessionId: string;
  clientOAuthSessionId: string;
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
};

export const getIpvSessionByAuthCode = async (authCode: string): Promise<IpvSessionItem> => {
  const queryResult = await dynamoClient.query({
    TableName: TABLE_NAME,
    IndexName: 'authorizationCode',
    KeyConditionExpression: 'authorizationCode = :a',
    ExpressionAttributeValues: {
      ':a': authCode,
    },
  });

  if (!queryResult.Items) {
    throw new Error('No IPV Session found for auth code');
  }

  return unmarshall(queryResult.Items[0]) as IpvSessionItem;
};

export const updateIpvSession = async (ipvSession: IpvSessionItem): Promise<void> => {
  await dynamoClient.put({
    TableName: TABLE_NAME,
    Item: ipvSession,
  });
};
