package uk.gov.di.ipv.core.processasynccricredential;

import com.amazonaws.services.lambda.runtime.Context;
import com.amazonaws.services.lambda.runtime.RequestHandler;
import com.amazonaws.services.lambda.runtime.events.SQSBatchResponse;
import com.amazonaws.services.lambda.runtime.events.SQSEvent;
import com.amazonaws.services.lambda.runtime.events.SQSEvent.SQSMessage;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.apache.logging.log4j.Level;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import software.amazon.lambda.powertools.logging.Logging;
import software.amazon.lambda.powertools.tracing.Tracing;
import uk.gov.di.ipv.core.library.annotations.ExcludeFromGeneratedCoverageReport;
import uk.gov.di.ipv.core.library.service.ConfigService;
import uk.gov.di.ipv.core.processasynccricredential.dto.CriResponseMessage;

import java.util.ArrayList;
import java.util.List;

public class ProcessAsyncCriCredentialHandler
        implements RequestHandler<SQSEvent, SQSBatchResponse> {
    private static final Logger LOGGER = LogManager.getLogger();
    private static final ObjectMapper mapper = new ObjectMapper();
    private final ConfigService configService;

    public ProcessAsyncCriCredentialHandler(ConfigService configService) {
        this.configService = configService;
    }

    @ExcludeFromGeneratedCoverageReport
    public ProcessAsyncCriCredentialHandler() {
        this.configService = new ConfigService();
    }

    @Override
    @Tracing
    @Logging(clearState = true)
    public SQSBatchResponse handleRequest(SQSEvent event, Context context) {
        List<SQSBatchResponse.BatchItemFailure> failedRecords = new ArrayList<>();
        LOGGER.log(Level.INFO, event);
        for (SQSMessage message : event.getRecords()) {
            LOGGER.log(Level.INFO, message);
            try {
                final CriResponseMessage criResponseMessage =
                        mapper.readerFor(CriResponseMessage.class).readValue(message.getBody());
            } catch (JsonProcessingException e) {
                LOGGER.error("Failed to deserialise message");
                failedRecords.add(new SQSBatchResponse.BatchItemFailure(message.getMessageId()));
            }
        }
        return SQSBatchResponse.builder().withBatchItemFailures(failedRecords).build();
    }
}
