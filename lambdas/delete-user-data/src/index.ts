import { SQSEvent } from "aws-lambda";
import { readSNSMessage } from "./read-message";

export const handler = async (event: SQSEvent): Promise<void> => {
  if (!event?.Records?.[0].body) {
    throw new TypeError("no event provided");
  }
  const message = readSNSMessage(event.Records[0].body);
  console.log("User id requiring account deletion:", message.user_id);
};
