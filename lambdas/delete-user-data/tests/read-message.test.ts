import { SNSEvent } from "aws-lambda";
import { buildMockSnsEvent } from "./mock-sns-event";
import { readMessage } from "../src/read-message";
import { Message } from "../src/types";

describe("readMessage", () => {
  let mockEvent: SNSEvent;
  beforeEach(() => {
    mockEvent = buildMockSnsEvent();
  });

  test("parses and validates message from SNS event", () => {
    const expectedMessage: Message = {
      user_id: "123",
    };
    expect(readMessage(mockEvent)).toStrictEqual(expectedMessage);
  });

  test("throws error if no user id in the message", () => {
    mockEvent.Records[0].Sns.Message = '{ "not_user_id": "foo" }';
    expect(() => readMessage(mockEvent)).toThrow(TypeError);
  });

  test("throws error if user id is not a string", () => {
    mockEvent.Records[0].Sns.Message = '{ "user_id": 123 }';
    expect(() => readMessage(mockEvent)).toThrow(TypeError);
  });
});
