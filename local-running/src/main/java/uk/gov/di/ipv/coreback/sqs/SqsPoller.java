package uk.gov.di.ipv.coreback.sqs;

import com.amazonaws.services.lambda.runtime.RequestHandler;
import com.amazonaws.services.lambda.runtime.events.SQSBatchResponse;
import com.amazonaws.services.lambda.runtime.events.SQSEvent;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import uk.gov.di.ipv.core.library.helpers.LogHelper;

import java.util.concurrent.ScheduledThreadPoolExecutor;
import java.util.concurrent.TimeUnit;

public class SqsPoller {
    private static final Logger LOGGER = LogManager.getLogger();

    public void start(RequestHandler<SQSEvent, SQSBatchResponse> sqsHandler) {
        LOGGER.info(LogHelper.buildLogMessage("SQS poller starting up"));
        ScheduledThreadPoolExecutor threadPool = new ScheduledThreadPoolExecutor(2);
        threadPool.scheduleAtFixedRate(new SqsReader(sqsHandler), 2, 2, TimeUnit.SECONDS);
    }
}
