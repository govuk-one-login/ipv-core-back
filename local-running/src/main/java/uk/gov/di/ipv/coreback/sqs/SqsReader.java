package uk.gov.di.ipv.coreback.sqs;

import com.amazonaws.services.lambda.runtime.RequestHandler;
import com.amazonaws.services.lambda.runtime.events.SQSBatchResponse;
import com.amazonaws.services.lambda.runtime.events.SQSEvent;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import software.amazon.awssdk.http.urlconnection.UrlConnectionHttpClient;
import software.amazon.awssdk.services.sqs.SqsClient;
import software.amazon.awssdk.services.sqs.model.DeleteMessageRequest;
import software.amazon.awssdk.services.sqs.model.Message;
import software.amazon.awssdk.services.sqs.model.ReceiveMessageRequest;
import uk.gov.di.ipv.coreback.domain.CoreContext;

import java.util.ArrayList;
import java.util.List;

import static software.amazon.awssdk.regions.Region.EU_WEST_2;

public class SqsReader implements Runnable {
    private static final Logger LOGGER = LogManager.getLogger();
    private final SqsClient sqs;
    private final String queueUrl;
    private final RequestHandler<SQSEvent, SQSBatchResponse> sqsHandler;

    public SqsReader(RequestHandler<SQSEvent, SQSBatchResponse> sqsHandler) {
        this.sqs =
                SqsClient.builder()
                        .region(EU_WEST_2)
                        .httpClientBuilder(UrlConnectionHttpClient.builder())
                        .build();
        this.queueUrl =
                String.format(
                        "https://sqs.eu-west-2.amazonaws.com/616199614141/%s",
                        System.getenv("F2F_STUB_QUEUE_NAME"));
        this.sqsHandler = sqsHandler;
    }

    @Override
    public void run() {
        List<Message> messages =
                sqs.receiveMessage(ReceiveMessageRequest.builder().queueUrl(queueUrl).build())
                        .messages();
        if (!messages.isEmpty()) {
            LOGGER.info("Received {} message(s) from F2F SQS queue", messages.size());
            List<SQSEvent.SQSMessage> sqsEventRecords = new ArrayList<>();
            for (Message message : messages) {
                SQSEvent.SQSMessage sqsMessage = new SQSEvent.SQSMessage();
                sqsMessage.setMessageId(message.messageId());
                sqsMessage.setReceiptHandle(message.receiptHandle());
                sqsMessage.setBody(message.body());
                sqsMessage.setMd5OfBody(message.md5OfBody());
                sqsMessage.setMd5OfMessageAttributes(message.md5OfMessageAttributes());
                sqsMessage.setAttributes(message.attributesAsStrings());
                sqsEventRecords.add(sqsMessage);
                sqs.deleteMessage(
                        DeleteMessageRequest.builder()
                                .queueUrl(queueUrl)
                                .receiptHandle(message.receiptHandle())
                                .build());
            }
            SQSEvent sqsEvent = new SQSEvent();
            sqsEvent.setRecords(sqsEventRecords);

            sqsHandler.handleRequest(sqsEvent, new CoreContext());
        }
    }
}
