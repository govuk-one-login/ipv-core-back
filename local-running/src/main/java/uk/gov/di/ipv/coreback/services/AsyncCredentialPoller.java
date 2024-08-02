package uk.gov.di.ipv.coreback.services;

import com.amazonaws.services.lambda.runtime.events.SQSEvent;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import uk.gov.di.ipv.core.library.helpers.LogHelper;
import uk.gov.di.ipv.core.processasynccricredential.ProcessAsyncCriCredentialHandler;
import uk.gov.di.ipv.coreback.domain.CoreContext;

import java.io.IOException;
import java.net.URI;
import java.net.URISyntaxException;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.util.List;

public class AsyncCredentialPoller extends Thread {
    private static final Logger LOGGER = LogManager.getLogger();
    private static final ObjectMapper OBJECT_MAPPER = new ObjectMapper();
    private static final String X_API_KEY_HEADER = "x-api-key";
    private static final int SLEEP_AFTER_ERROR_MILLIS = 5000;

    private final URI queueUri;
    private final String queueApiKey;
    private final ProcessAsyncCriCredentialHandler processAsyncCriCredentialHandler;
    private final HttpClient httpClient;

    public AsyncCredentialPoller(String queueUri, String queueApiKey, String queueName)
            throws URISyntaxException {
        this.queueUri = new URI(queueUri + "/queues/" + queueName);
        this.queueApiKey = queueApiKey;
        this.processAsyncCriCredentialHandler = new ProcessAsyncCriCredentialHandler();
        this.httpClient = HttpClient.newHttpClient();
    }

    @Override
    public void run() {
        LOGGER.info(LogHelper.buildLogMessage("Async credential poller starting up"));
        while (true) {
            try {
                poll();
            } catch (InterruptedException e) {
                this.interrupt();
                break;
            }
        }
    }

    private void poll() throws InterruptedException {
        try {
            var request =
                    HttpRequest.newBuilder()
                            .uri(queueUri)
                            .header(X_API_KEY_HEADER, queueApiKey)
                            .GET()
                            .build();
            var response = httpClient.send(request, HttpResponse.BodyHandlers.ofString());
            if (response.statusCode() == 200) {
                LOGGER.info(LogHelper.buildLogMessage("Poll received message"));
                var message = OBJECT_MAPPER.readValue(response.body(), SQSEvent.SQSMessage.class);
                var sqsEvent = new SQSEvent();
                sqsEvent.setRecords(List.of(message));
                processAsyncCriCredentialHandler.handleRequest(sqsEvent, new CoreContext());
            } else if (response.statusCode() == 204) {
                LOGGER.info(LogHelper.buildLogMessage("Poll received no messages"));
            } else {
                throw new IOException("Request failed with status code " + response.statusCode());
            }
        } catch (IOException e) {
            LOGGER.error(
                    LogHelper.buildErrorMessage(
                            "Exception polling from async credential queue", e));
            sleep(SLEEP_AFTER_ERROR_MILLIS);
        }
    }
}
