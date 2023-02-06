import { SQSClient, SendMessageCommandInput, SendMessageCommand } from "@aws-sdk/client-sqs";
import { config } from "./config";
import { logger } from "./logger";
import { AuditEvent, AuditUser } from "./types";

const sqsClient = new SQSClient({ region: "eu-west-2" });

export const sendAuditEvent = async (
  eventName: string,
  user: AuditUser,
  extensions?: Record<string, unknown>
): Promise<void> => {
  logger.info("Sending audit event", { event: { name: eventName } });

  const auditEvent: AuditEvent = {
    timestamp: Math.trunc(Date.now() / 1000),
    component_id: config.componentId,
    event_name: eventName,
    user,
  };
  if (extensions) auditEvent.extensions = extensions;

  const input: SendMessageCommandInput = {
    MessageBody: JSON.stringify(auditEvent),
    QueueUrl: config.sqsAuditEventQueueUrl,
  };
  try {
    await sqsClient.send(new SendMessageCommand(input));
  } catch (e) {
    logger.error("Error sending audit event", e as Error);
  }
};
