export const config = {
  componentId: "ipv-core-delete-user-data",
  userIssuedCredentialsTableName: process.env.USER_ISSUED_CREDENTIALS_TABLE_NAME || "",
  sqsAuditEventQueueUrl: process.env.SQS_AUDIT_EVENT_QUEUE_URL || "",
};
