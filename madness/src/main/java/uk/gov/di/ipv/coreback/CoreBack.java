package uk.gov.di.ipv.coreback;

import spark.Spark;
import uk.gov.di.ipv.coreback.handlers.HomeHandler;
import uk.gov.di.ipv.coreback.handlers.LambdaHandler;

import java.io.IOException;

public class CoreBack {
    public CoreBack() throws IOException {
        LambdaHandler lambdaHandler = new LambdaHandler();
        Spark.port(5678);
        Spark.get("/", HomeHandler.serveHomePage);

        Spark.post("/session/initialise", lambdaHandler.initialiseSession);
        Spark.post("/journey/:event", lambdaHandler.journeyEngine);
        Spark.get(
                "/journey/build-proven-user-identity-details",
                lambdaHandler.buildProvenUserIdentityDetails);
        Spark.post("/journey/cri/callback", lambdaHandler.criCallBack);

        Spark.post("/token", lambdaHandler.token);
        Spark.get("/user-identity", lambdaHandler.userIdentity);

        Spark.internalServerError("🤮");
    }
}
