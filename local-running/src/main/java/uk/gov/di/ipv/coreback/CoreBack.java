package uk.gov.di.ipv.coreback;

import io.javalin.Javalin;
import uk.gov.di.ipv.core.library.service.ConfigService;
import uk.gov.di.ipv.core.library.service.YamlConfigService;
import uk.gov.di.ipv.coreback.handlers.AuditHandler;
import uk.gov.di.ipv.coreback.handlers.HomeHandler;
import uk.gov.di.ipv.coreback.handlers.JourneyEngineHandler;
import uk.gov.di.ipv.coreback.handlers.LambdaHandler;
import uk.gov.di.ipv.coreback.services.AsyncCredentialPoller;

import java.io.IOException;
import java.net.URISyntaxException;

public class CoreBack {
    private static final int DEFAULT_PORT = 4502;

    public CoreBack() throws IOException, URISyntaxException {
        ConfigService.setLocal(true);

        var lambdaHandler = new LambdaHandler();
        var journeyEngineHandler = new JourneyEngineHandler();
        var auditHandler = new AuditHandler();

        var app = Javalin.create();

        // Test APIs
        app.get("/", HomeHandler::serveHomePage);
        app.get("/audit-events", auditHandler::getAuditEvents);

        // Internal APIs
        app.post("/session/initialise", lambdaHandler::initialiseSession);
        app.post("/journey/{event}", journeyEngineHandler::journeyEngine);
        app.post("/cri/callback", lambdaHandler::criCallback);
        app.get("/user/proven-identity-details", lambdaHandler::getProvenUserIdentityDetails);

        // External APIs
        app.post("/token", lambdaHandler::getToken);
        app.get("/user-identity", lambdaHandler::getUserIdentity);
        app.get("/reverification", lambdaHandler::getUserReverification);

        // Poll for async credentials
        startAsyncPoller();

        // Start app
        app.start(getPort());
    }

    private int getPort() {
        var envPort = System.getenv("PORT");
        return envPort == null ? DEFAULT_PORT : Integer.parseInt(envPort);
    }

    private void startAsyncPoller() throws URISyntaxException {
        var configService = new YamlConfigService();
        var asyncQueueUrl = configService.getParameter("local/asyncQueue/apiBaseUrl");
        var asyncQueueApiKey = configService.getSecret("local/asyncQueue/apiKey");
        var asyncQueueName = configService.getSecret("local/asyncQueue/queueName");

        if (!"QUEUE_NAME".equals(asyncQueueName)) {
            var pollerThread =
                    new AsyncCredentialPoller(asyncQueueUrl, asyncQueueApiKey, asyncQueueName);
            pollerThread.setDaemon(true);
            pollerThread.start();
        }
    }
}
