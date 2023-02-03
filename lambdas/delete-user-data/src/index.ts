import { Context, SQSEvent } from "aws-lambda";
import { deleteVCs } from "./delete-data";
import { logger } from "./logger";
import { readSNSMessage } from "./read-message";

export const handler = async (event: SQSEvent, context: Context): Promise<void> => {
  logger.addContext(context);
  if (!event?.Records?.[0].body) {
    throw new TypeError("no event provided");
  }
  const message = readSNSMessage(event.Records[0].body);
  await deleteVCs(message.user_id);
};
