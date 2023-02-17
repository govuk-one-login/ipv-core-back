import { SQSEvent } from "aws-lambda";
import { ContextExamples } from "@aws-lambda-powertools/commons";
import { handler } from "../src";
import { deleteVCs } from "../src/delete-data";
import { buildMockSQSEvent } from "./mock-sqs-event";

jest.mock("../src/delete-data");
const mockDeleteVCs = deleteVCs as jest.Mocked<typeof deleteVCs>;

jest.mock("../src/utils/send-audit-event", () => ({
  sendAuditEvent: jest.fn(),
}));

describe("handler", () => {
  const mockContext = ContextExamples.helloworldContext;
  let mockSQSEvent: SQSEvent;
  beforeEach(() => {
    mockSQSEvent = buildMockSQSEvent();
  });

  test("deletes VCs for user id in incoming SNS message", async () => {
    await handler(mockSQSEvent, mockContext);

    expect(mockDeleteVCs).toHaveBeenCalledWith("123");
  });

  test("throws error if no event found", async () => {
    mockSQSEvent = { something: "else" } as any;
    await expect(handler(mockSQSEvent, mockContext)).rejects.toThrow(TypeError);
  });
});
