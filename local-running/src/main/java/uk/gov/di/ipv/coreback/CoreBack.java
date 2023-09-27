package uk.gov.di.ipv.coreback;

import spark.Spark;
import uk.gov.di.ipv.coreback.handlers.HomeHandler;
import uk.gov.di.ipv.coreback.handlers.LambdaHandler;

import java.io.IOException;

public class CoreBack {
    public CoreBack() throws IOException {
        LambdaHandler lambdaHandler = new LambdaHandler();
        Spark.port(Integer.parseInt(System.getenv("PORT")));
        Spark.get("/", HomeHandler.serveHomePage);

        Spark.post("/session/initialise", lambdaHandler.getInitialiseSession());
        Spark.post("/journey/:event", lambdaHandler.getJourneyEngine());
        Spark.get(
                "/journey/build-proven-user-identity-details",
                lambdaHandler.getBuildProvenUserIdentityDetails());
        Spark.post("/journey/cri/callback", lambdaHandler.getCriCallBack());

        Spark.post("/token", lambdaHandler.getToken());
        Spark.get("/user-identity", lambdaHandler.getUserIdentity());

        Spark.internalServerError("🤮");
    }
}
