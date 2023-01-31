import { SQSEvent } from "aws-lambda";
import { handler } from "../src";
import { buildMockSQSEvent } from "./mock-sqs-event";

describe("handler", () => {
  let mockSQSEvent: SQSEvent;
  beforeEach(() => {
    mockSQSEvent = buildMockSQSEvent();
  });

  test("reads an incoming SQS event", async () => {
    await expect(handler(mockSQSEvent)).resolves.toBeUndefined();
  });

  test("throws error if no event found", async () => {
    mockSQSEvent = { something: "else" } as any;
    await expect(handler(mockSQSEvent)).rejects.toThrow(TypeError);
  });
});
