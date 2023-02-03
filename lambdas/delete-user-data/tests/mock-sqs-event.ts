import { SQSEvent } from "aws-lambda";

export const buildMockSQSEvent = (): SQSEvent => ({
  Records: [
    {
      messageId: "001",
      receiptHandle: "receiptHandle",
      attributes: {
        ApproximateReceiveCount: "ApproximateReceiveCount",
        SentTimestamp: "SentTimestamp",
        SenderId: "SenderId",
        ApproximateFirstReceiveTimestamp: "ApproximateFirstReceiveTimestamp",
      },
      messageAttributes: {},
      md5OfBody: "md5OfBody",
      eventSource: "eventSource",
      eventSourceARN: "eventSourceARN",
      awsRegion: "awsRegion",
      body: JSON.stringify({
        Signature: "EXAMPLE",
        MessageId: "95df01b4-ee98-5cb9-9903-4c221d41eb5e",
        Type: "Notification",
        TopicArn: "arn:aws:sns:EXAMPLE",
        MessageAttributes: {},
        SignatureVersion: "1",
        Timestamp: "2015-06-03T17:43:27.123Z",
        SigningCertUrl: "EXAMPLE",
        Message: '{ "user_id": "123" }',
        UnsubscribeUrl: "EXAMPLE",
        Subject: "TestInvoke",
      }),
    },
  ],
});
