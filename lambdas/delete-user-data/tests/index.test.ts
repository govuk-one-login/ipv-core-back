import { SQSEvent } from "aws-lambda";
import { handler } from "../src";
import { deleteVCs } from "../src/delete-data";
import { buildMockSQSEvent } from "./mock-sqs-event";

jest.mock("../src/delete-data");
const mockDeleteVCs = deleteVCs as jest.Mocked<typeof deleteVCs>;

describe("handler", () => {
  let mockSQSEvent: SQSEvent;
  beforeEach(() => {
    mockSQSEvent = buildMockSQSEvent();
  });

  test("deletes VCs for user id in incoming SNS message", async () => {
    await handler(mockSQSEvent);

    expect(mockDeleteVCs).toHaveBeenCalledWith("123");
  });

  test("throws error if no event found", async () => {
    mockSQSEvent = { something: "else" } as any;
    await expect(handler(mockSQSEvent)).rejects.toThrow(TypeError);
  });
});
