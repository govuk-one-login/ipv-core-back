package uk.gov.di.ipv.coreback.sqs;

import com.amazonaws.services.lambda.runtime.RequestHandler;
import com.amazonaws.services.lambda.runtime.events.SQSBatchResponse;
import com.amazonaws.services.lambda.runtime.events.SQSEvent;
import com.amazonaws.services.sqs.AmazonSQS;
import com.amazonaws.services.sqs.AmazonSQSClientBuilder;
import com.amazonaws.services.sqs.model.Message;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import uk.gov.di.ipv.coreback.domain.CoreContext;

import java.util.ArrayList;
import java.util.List;

public class SqsReader implements Runnable {
    private static final Logger LOGGER = LogManager.getLogger();
    private final AmazonSQS sqs;
    private final String queueUrl;
    private final RequestHandler<SQSEvent, SQSBatchResponse> sqsHandler;

    public SqsReader(RequestHandler<SQSEvent, SQSBatchResponse> sqsHandler) {
        this.sqs = AmazonSQSClientBuilder.defaultClient();
        this.queueUrl =
                String.format(
                        "https://sqs.eu-west-2.amazonaws.com/616199614141/%s",
                        System.getenv("F2F_STUB_QUEUE_NAME"));
        this.sqsHandler = sqsHandler;
    }

    @Override
    public void run() {
        List<Message> messages = sqs.receiveMessage(queueUrl).getMessages();
        if (!messages.isEmpty()) {
            LOGGER.info("Received {} message(s) from F2F SQS queue", messages.size());
            List<SQSEvent.SQSMessage> sqsEventRecords = new ArrayList<>();
            for (Message message : messages) {
                SQSEvent.SQSMessage sqsMessage = new SQSEvent.SQSMessage();
                sqsMessage.setMessageId(message.getMessageId());
                sqsMessage.setReceiptHandle(message.getReceiptHandle());
                sqsMessage.setBody(message.getBody());
                sqsMessage.setMd5OfBody(message.getMD5OfBody());
                sqsMessage.setMd5OfMessageAttributes(message.getMD5OfMessageAttributes());
                sqsMessage.setAttributes(message.getAttributes());
                sqsEventRecords.add(sqsMessage);
                sqs.deleteMessage(queueUrl, message.getReceiptHandle());
            }
            SQSEvent sqsEvent = new SQSEvent();
            sqsEvent.setRecords(sqsEventRecords);

            sqsHandler.handleRequest(sqsEvent, new CoreContext());
        }
    }
}
