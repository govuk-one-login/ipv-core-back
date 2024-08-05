package uk.gov.di.ipv.coreback;

import io.javalin.Javalin;
import uk.gov.di.ipv.core.library.service.ConfigService;
import uk.gov.di.ipv.core.processasynccricredential.ProcessAsyncCriCredentialHandler;
import uk.gov.di.ipv.coreback.handlers.AuditHandler;
import uk.gov.di.ipv.coreback.handlers.HomeHandler;
import uk.gov.di.ipv.coreback.handlers.JourneyEngineHandler;
import uk.gov.di.ipv.coreback.handlers.LambdaHandler;
import uk.gov.di.ipv.coreback.sqs.SqsPoller;

import java.io.IOException;

public class CoreBack {
    private static final int DEFAULT_PORT = 4502;

    public CoreBack() throws IOException {
        ConfigService.setLocal(true);

        var lambdaHandler = new LambdaHandler();
        var journeyEngineHandler = new JourneyEngineHandler();
        var auditHandler = new AuditHandler();

        new SqsPoller().start(new ProcessAsyncCriCredentialHandler());

        var app = Javalin.create().start(getPort());

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
    }

    private int getPort() {
        var envPort = System.getenv("PORT");
        return envPort == null ? DEFAULT_PORT : Integer.parseInt(envPort);
    }
}
