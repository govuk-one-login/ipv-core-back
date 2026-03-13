package uk.gov.di.ipv.coreback;

import io.javalin.Javalin;
import uk.gov.di.ipv.core.library.service.ConfigService;
import uk.gov.di.ipv.core.library.service.LocalConfigService;
import uk.gov.di.ipv.coreback.handlers.AuditHandler;
import uk.gov.di.ipv.coreback.handlers.DidHandler;
import uk.gov.di.ipv.coreback.handlers.HomeHandler;
import uk.gov.di.ipv.coreback.handlers.JourneyEngineHandler;
import uk.gov.di.ipv.coreback.handlers.JwksHandler;
import uk.gov.di.ipv.coreback.handlers.LambdaHandler;
import uk.gov.di.ipv.coreback.services.AsyncCredentialPoller;

import java.io.IOException;
import java.net.URISyntaxException;
import java.util.Map;

public class CoreBack {
    private static final int DEFAULT_PORT = 4502;

    public CoreBack() throws IOException, URISyntaxException {
        ConfigService.setLocal(true);

        var lambdaHandler = new LambdaHandler();
        var journeyEngineHandler = new JourneyEngineHandler();
        var auditHandler = new AuditHandler();
        var jwksHandler = new JwksHandler();

        var app =
                Javalin.create(
                        config -> {
                            // Test APIs
                            config.routes.get("/", HomeHandler::serveHomePage);
                            config.routes.get("/audit-events", auditHandler::getAuditEvents);

                            // Internal APIs
                            config.routes.post(
                                    "/session/initialise", lambdaHandler::initialiseSession);
                            config.routes.post(
                                    "/journey/{event}", journeyEngineHandler::journeyEngine);
                            config.routes.post("/cri/callback", lambdaHandler::criCallback);
                            config.routes.post("/app/callback", lambdaHandler::appCallback);
                            config.routes.get(
                                    "/app/check-vc-receipt",
                                    lambdaHandler::checkMobileAppVcReceipt);
                            config.routes.get(
                                    "/user/proven-identity-details",
                                    lambdaHandler::getProvenUserIdentityDetails);

                            // External APIs
                            config.routes.post("/token", lambdaHandler::getToken);
                            config.routes.get("/user-identity", lambdaHandler::getUserIdentity);
                            config.routes.get(
                                    "/reverification", lambdaHandler::getUserReverification);
                            config.routes.get(
                                    "/healthcheck", (ctx) -> ctx.json(Map.of("healthcheck", "ok")));
                            config.routes.get("/.well-known/jwks.json", jwksHandler::jwks);
                            config.routes.get(
                                    "/.well-known/stored-identity/did.json", DidHandler::did);
                        });

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
        var configService = new LocalConfigService();
        String asyncQueueUrl =
                configService.getConfiguration().getLocal().get("asyncQueue").get("apiBaseUrl");
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
