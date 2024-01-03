package uk.gov.di.ipv.coreback.sqs;

import com.amazonaws.services.lambda.runtime.RequestHandler;
import com.amazonaws.services.lambda.runtime.events.SQSBatchResponse;
import com.amazonaws.services.lambda.runtime.events.SQSEvent;
import org.apache.logging.log4j.Level;
import uk.gov.di.ipv.core.library.helpers.LogHelper;

import java.util.concurrent.ScheduledThreadPoolExecutor;
import java.util.concurrent.TimeUnit;

public class SqsPoller {
    public void start(RequestHandler<SQSEvent, SQSBatchResponse> sqsHandler) {
        LogHelper.logMessage(Level.INFO, "SQS poller starting up");
        ScheduledThreadPoolExecutor threadPool = new ScheduledThreadPoolExecutor(2);
        threadPool.scheduleAtFixedRate(new SqsReader(sqsHandler), 2, 2, TimeUnit.SECONDS);
    }
}
