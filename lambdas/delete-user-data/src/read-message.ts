import { SNSEvent } from "aws-lambda";
import { Message } from "./types";

export const readMessage = (event: SNSEvent): Message => {
  const message: unknown = JSON.parse(event.Records[0].Sns.Message);
  validateMessage(message);
  return message;
};

const validateMessage: (input: unknown) => asserts input is Message = (input) => {
  if (input === null || typeof input !== "object" || !("user_id" in input)) {
    throw new TypeError("message must be an object containing user_id");
  }
  if (typeof input.user_id !== "string") {
    throw new TypeError("user_id in message object must be a string");
  }
};
