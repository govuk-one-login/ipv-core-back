import { SNSMessage } from "aws-lambda";
import { readSNSMessage } from "../src/read-message";
import { Message } from "../src/types";

describe("readSNSMessage", () => {
  const mockTopicARN = "arn:aws:sns:EXAMPLE";
  let mockBody: SNSMessage;
  beforeEach(() => {
    mockBody = {
      Signature: "EXAMPLE",
      MessageId: "95df01b4-ee98-5cb9-9903-4c221d41eb5e",
      Type: "Notification",
      TopicArn: mockTopicARN,
      MessageAttributes: {},
      SignatureVersion: "1",
      Timestamp: "2015-06-03T17:43:27.123Z",
      SigningCertUrl: "EXAMPLE",
      Message: '{ "user_id": "123" }',
      UnsubscribeUrl: "EXAMPLE",
      Subject: "TestInvoke",
    };
  });

  test("parses and validates SNS message", () => {
    const expectedMessage: Message = {
      user_id: "123",
    };
    const { message } = readSNSMessage(JSON.stringify(mockBody));
    expect(message).toStrictEqual(expectedMessage);
  });

  test("returns the source topic ARN alongside the message", () => {
    const { topicARN } = readSNSMessage(JSON.stringify(mockBody));
    expect(topicARN).toBe(mockTopicARN);
  });

  test("throws error if no user id in the message", () => {
    mockBody.Message = '{ "not_user_id": "foo" }';
    expect(() => readSNSMessage(JSON.stringify(mockBody))).toThrow(TypeError);
  });

  test("throws error if user id is not a string", () => {
    mockBody.Message = '{ "user_id": 123 }';
    expect(() => readSNSMessage(JSON.stringify(mockBody))).toThrow(TypeError);
  });
});
