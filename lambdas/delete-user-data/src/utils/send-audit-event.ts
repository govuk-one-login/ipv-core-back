import { SQSClient, SendMessageCommand } from "@aws-sdk/client-sqs";
import { config } from "../config";
import { getConfigParam } from "./get-config-param";
import { logger } from "./logger";
import { AuditEvent, AuditUser } from "../types";

const sqsClient = new SQSClient({ region: "eu-west-2" });

export const sendAuditEvent = async (
  eventName: string,
  user: AuditUser,
  extensions?: Record<string, unknown>
): Promise<void> => {
  if (config.isLocalDev) {
    logger.info("Local dev so skipping audit event", { eventName, user, extensions });
    return;
  }
  logger.info("Sending audit event", { event: { name: eventName } });
  try {
    const componentId = await getConfigParam("core/self/componentId");
    const auditEvent: AuditEvent = {
      timestamp: Math.trunc(Date.now() / 1000),
      component_id: componentId,
      event_name: eventName,
      user,
    };
    if (extensions) auditEvent.extensions = extensions;
    await sqsClient.send(
      new SendMessageCommand({
        MessageBody: JSON.stringify(auditEvent),
        QueueUrl: config.sqsAuditEventQueueUrl,
      })
    );
  } catch (e) {
    logger.error("Error sending audit event", e as Error);
  }
};
