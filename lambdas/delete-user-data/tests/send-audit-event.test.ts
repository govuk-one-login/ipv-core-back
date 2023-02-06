import { config } from "../src/config";
import { sendAuditEvent } from "../src/send-audit-event";
import { AuditUser } from "../src/types";

jest.mock("../src/config");

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
    config.componentId = mockComponentId;
  });

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
    };

    await sendAuditEvent(mockAuditEventName, mockAuditUser);

    expect(mockSQSSend).toHaveBeenCalledWith(
      expect.objectContaining({
        input: {
          MessageBody: JSON.stringify(expectedAuditEvent),
          QueueUrl: mockQueueUrl,
        },
      })
    );
  });

  describe("audit extensions property", () => {
    test("when extensions is passed in AuditEvent should contain extensions", () => {
      const expectedAuditEvent = {
        timestamp: Math.trunc(Date.now() / 1000),
        component_id: mockComponentId,
        event_name: mockAuditEventName,
        user: mockAuditUser,
        extensions: { prop1: "prop1_value" },
      };

      sendAuditEvent(mockAuditEventName, mockAuditUser, {
        prop1: "prop1_value",
      });

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
});
