import { config } from "../src/config";
import { sendAuditEvent } from "../src/send-audit-event";
import { AuditUser } from "../src/types";

jest.mock("../src/config");

jest.mock("../src/get-config-param", () => ({
  getConfigParam: () => "component-id",
}));

const mockSQSSend = jest.fn();
jest.mock("@aws-sdk/client-sqs", () => ({
  SQSClient: jest.fn().mockImplementation(() => ({
    send: (sendCommand: any) => mockSQSSend(sendCommand),
  })),
  SendMessageCommand: jest.fn().mockImplementation((input) => ({ input })),
}));

describe("sendAuditEvent", () => {
  const now = new Date();
  const mockQueueUrl = "queue-url.com";
  const mockComponentId = "component-id";
  const mockAuditEventName = "IPV_DELETE_USER_DATA";
  const mockAuditUser: AuditUser = {
    user_id: "78912",
  };

  beforeAll(() => {
    jest.useFakeTimers();
    jest.setSystemTime(now);
  });

  beforeEach(() => {
    config.sqsAuditEventQueueUrl = mockQueueUrl;
  });

  afterEach(jest.clearAllMocks);

  afterAll(() => {
    jest.resetAllMocks();
    jest.useRealTimers();
  });

  test("sends audit event to SQS queue", async () => {
    const expectedAuditEvent = {
      timestamp: Math.trunc(Date.now() / 1000),
      component_id: mockComponentId,
      event_name: mockAuditEventName,
      user: mockAuditUser,
      extensions: { foo: "bar" },
    };

    await sendAuditEvent(mockAuditEventName, mockAuditUser, { foo: "bar" });

    expect(mockSQSSend).toHaveBeenCalledWith(
      expect.objectContaining({
        input: {
          MessageBody: JSON.stringify(expectedAuditEvent),
          QueueUrl: mockQueueUrl,
        },
      })
    );
  });
});
