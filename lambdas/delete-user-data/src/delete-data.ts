import { DynamoDBClient } from "@aws-sdk/client-dynamodb";
import { DynamoDBDocument } from "@aws-sdk/lib-dynamodb";
import { config } from "./config";
import { logger } from "./utils/logger";
import { VCItemKey } from "./types";

const ddbDocClient = DynamoDBDocument.from(
  config.isLocalDev
    ? new DynamoDBClient({ endpoint: config.localDynamoDbEndpoint })
    : new DynamoDBClient({ region: "eu-west-2" }),
);

export const deleteVCs = async (userId: string): Promise<number> => {
  const keysToDelete = await getVCItemKeys(userId);
  const deleteCount = keysToDelete.length;
  if (deleteCount === 0) {
    return 0;
  }
  const deletePromises = keysToDelete.map((key) =>
    ddbDocClient.delete({
      TableName: config.userIssuedCredentialsTableName,
      Key: key,
    }),
  );
  await Promise.all(deletePromises);
  logger.info("Deleted user's VCs", { count: deleteCount });
  return deleteCount;
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
    logger.info("No VCs found for user");
    return [];
  }
  logger.info("Found user's VCs", { count: itemKeys.length });
  return itemKeys as VCItemKey[];
};
