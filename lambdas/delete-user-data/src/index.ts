import { SQSEvent } from "aws-lambda";
import { deleteVCs } from "./delete-data";
import { readSNSMessage } from "./read-message";

export const handler = async (event: SQSEvent): Promise<void> => {
  if (!event?.Records?.[0].body) {
    throw new TypeError("no event provided");
  }
  const message = readSNSMessage(event.Records[0].body);
  await deleteVCs(message.user_id);
};
