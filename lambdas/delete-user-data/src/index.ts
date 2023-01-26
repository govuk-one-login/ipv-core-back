import { SNSEvent } from "aws-lambda";
import { readMessage } from "./read-message";

export const handler = async (event: SNSEvent): Promise<void> => {
  if (!event?.Records?.[0].Sns) {
    throw new TypeError("no SNS event provided");
  }
  const message = readMessage(event);
  console.log("User id requiring account deletion:", message.user_id);
};
