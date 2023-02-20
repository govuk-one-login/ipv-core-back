import { Context, SQSEvent } from "aws-lambda";
import { deleteVCs } from "./delete-data";
import { initialiseLogger } from "./utils/logger";
import { readSNSMessage } from "./read-message";
import { sendAuditEvent } from "./utils/send-audit-event";

export const handler = async (event: SQSEvent, context: Context): Promise<void> => {
  initialiseLogger(context);
  if (!event?.Records?.[0].body) {
    throw new TypeError("no event provided");
  }
  const { message, topicARN } = readSNSMessage(event.Records[0].body);
  const deleteCount = await deleteVCs(message.user_id);
  if (deleteCount > 0) {
    await sendAuditEvent("IPV_DELETE_USER_DATA", { user_id: message.user_id }, { source_topic_arn: topicARN });
  }
};
