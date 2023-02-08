export const config = {
  environment: process.env.ENVIRONMENT || "",
  userIssuedCredentialsTableName: process.env.USER_ISSUED_CREDENTIALS_TABLE_NAME || "",
  sqsAuditEventQueueUrl: process.env.SQS_AUDIT_EVENT_QUEUE_URL || "",
};
