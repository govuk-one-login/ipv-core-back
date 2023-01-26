import { SNSEvent } from "aws-lambda";
import { handler } from "../src";
import { buildMockSnsEvent } from "./mock-sns-event";

describe("handler", () => {
  let mockSnsEvent: SNSEvent;
  beforeEach(() => {
    mockSnsEvent = buildMockSnsEvent();
  });

  test("reads an incoming SNS notification", async () => {
    await expect(handler(mockSnsEvent)).resolves.toBeUndefined();
  });

  test("throws error if not an SNS notification", async () => {
    mockSnsEvent = { body: { user_id: "123" } } as any;
    await expect(handler(mockSnsEvent)).rejects.toThrow(TypeError);
  });
});
