package uk.gov.di.ipv.coreback;

import spark.Spark;
import uk.gov.di.ipv.core.processasynccricredential.ProcessAsyncCriCredentialHandler;
import uk.gov.di.ipv.coreback.handlers.HomeHandler;
import uk.gov.di.ipv.coreback.handlers.LambdaHandler;
import uk.gov.di.ipv.coreback.sqs.SqsPoller;

import java.io.IOException;

public class CoreBack {
    public CoreBack() throws IOException {
        LambdaHandler lambdaHandler = new LambdaHandler();

        new SqsPoller().start(new ProcessAsyncCriCredentialHandler());

        Spark.port(Integer.parseInt(System.getenv("PORT")));
        Spark.get("/", HomeHandler.serveHomePage);

        Spark.post("/session/initialise", lambdaHandler.getInitialiseSession());
        Spark.post("/journey/:event", lambdaHandler.getJourneyEngine());
        Spark.post("/cri/callback", lambdaHandler.getCriCallBack());
        Spark.get(
                "/user/proven-identity-details", lambdaHandler.getBuildProvenUserIdentityDetails());

        Spark.post("/token", lambdaHandler.getToken());
        Spark.get("/user-identity", lambdaHandler.getUserIdentity());

        Spark.internalServerError("🤮");
    }
}
