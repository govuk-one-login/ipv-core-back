export const config = {
  environment: process.env.ENVIRONMENT || "",
  isLocalDev: !!process.env.AWS_SAM_LOCAL,
  localDynamoDbEndpoint: process.env.LOCAL_DYNAMODB_ENDPOINT || "",
  userIssuedCredentialsTableName: process.env.USER_ISSUED_CREDENTIALS_TABLE_NAME || "",
  sqsAuditEventQueueUrl: process.env.SQS_AUDIT_EVENT_QUEUE_URL || "",
};
