import { DynamoDBClient } from "@aws-sdk/client-dynamodb";
import { DynamoDBDocument } from "@aws-sdk/lib-dynamodb";
import { config } from "./config";
import { VCItemKey } from "./types";

const ddbDocClient = DynamoDBDocument.from(new DynamoDBClient({ region: "eu-west-2" }));

export const deleteVCs = async (userId: string): Promise<void> => {
  const keysToDelete = await getVCItemKeys(userId);
  const deletePromises = keysToDelete.map((key) =>
    ddbDocClient.delete({
      TableName: config.userIssuedCredentialsTableName,
      Key: key,
    })
  );
  await Promise.all(deletePromises);
};

const getVCItemKeys = async (userId: string): Promise<VCItemKey[]> => {
  const { Items: itemKeys } = await ddbDocClient.query({
    TableName: config.userIssuedCredentialsTableName,
    ProjectionExpression: "userId, credentialIssuer",
    KeyConditionExpression: "userId = :userId",
    ExpressionAttributeValues: {
      ":userId": userId,
    },
  });
  if (!itemKeys || itemKeys.length === 0) {
    throw new Error("failed to find any VCs for user: " + userId);
  }
  return itemKeys as VCItemKey[];
};
