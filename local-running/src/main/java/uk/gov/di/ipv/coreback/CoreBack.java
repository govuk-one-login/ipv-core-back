package uk.gov.di.ipv.coreback;

import spark.Spark;
import uk.gov.di.ipv.core.library.service.ConfigService;
import uk.gov.di.ipv.core.processasynccricredential.ProcessAsyncCriCredentialHandler;
import uk.gov.di.ipv.coreback.handlers.HomeHandler;
import uk.gov.di.ipv.coreback.handlers.JourneyEngineHandler;
import uk.gov.di.ipv.coreback.handlers.LambdaHandler;
import uk.gov.di.ipv.coreback.sqs.SqsPoller;

import java.io.IOException;

public class CoreBack {
    private static final int DEFAULT_PORT = 3002;

    public CoreBack() throws IOException {
        ConfigService.IS_LOCAL = true;

        var lambdaHandler = new LambdaHandler();
        var journeyEngineHandler = new JourneyEngineHandler();

        new SqsPoller().start(new ProcessAsyncCriCredentialHandler());

        Spark.port(getPort());
        Spark.get("/", HomeHandler.serveHomePage);

        Spark.post("/session/initialise", lambdaHandler.getInitialiseSession());
        Spark.post("/journey/:event", journeyEngineHandler.getJourneyEngine());
        Spark.post("/cri/callback", lambdaHandler.getCriCallBack());
        Spark.get(
                "/user/proven-identity-details", lambdaHandler.getBuildProvenUserIdentityDetails());

        Spark.post("/token", lambdaHandler.getToken());
        Spark.get("/user-identity", lambdaHandler.getUserIdentity());

        Spark.get("/reverification", lambdaHandler.getUserReverification());

        Spark.internalServerError("🤮");
    }

    private int getPort() {
        var envPort = System.getenv("PORT");
        return envPort == null ? DEFAULT_PORT : Integer.parseInt(envPort);
    }
}
