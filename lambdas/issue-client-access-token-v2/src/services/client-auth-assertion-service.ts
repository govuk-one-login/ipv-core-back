import { DynamoDBClient } from "@aws-sdk/client-dynamodb";
import { DynamoDBDocument } from "@aws-sdk/lib-dynamodb";
import AWSXRay from "aws-xray-sdk";
import { ConfigKeys, getNumberConfigValue } from "./config-service";

const TABLE_NAME = process.env.CLIENT_AUTH_JWT_IDS_TABLE_NAME || 'ipv-client-auth-jwts-table';

const dynamoClient = DynamoDBDocument.from(
  AWSXRay.captureAWSv3Client(
    new DynamoDBClient({ region: "eu-west-2" })));

type ClientAuthAssertion = {
  jwtId: string;
  usedAtDateTime: string;
  ttl: number;
};

export const getClientAuthAssertion = async (jwtId: string): Promise<ClientAuthAssertion | null> => {
  const result = await dynamoClient.get({
    TableName: TABLE_NAME,
    Key: { jwtId },
  });

  return (result.Item as ClientAuthAssertion) || null;
};

export const persistClientAuthAssertion = async (jwtId: string): Promise<void> => {
  var item: ClientAuthAssertion = {
    jwtId,
    usedAtDateTime: new Date().toISOString(),
    ttl: Date.now() + (await getNumberConfigValue(ConfigKeys.backendSessionTtl) * 1000),
  };
  await dynamoClient.put({
    TableName: TABLE_NAME,
    Item: item,
  });
};
