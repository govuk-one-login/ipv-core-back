package uk.gov.di.ipv.coreback;

import spark.Spark;
import uk.gov.di.ipv.coreback.handlers.HomeHandler;
import uk.gov.di.ipv.coreback.handlers.LambdaHandler;

public class CoreBack {
    public CoreBack() {
        Spark.port(5678);
        Spark.get("/", HomeHandler.serveHomePage);

        Spark.post("/session/initialise", LambdaHandler.initialiseSession);
        Spark.post("/journey/:event", LambdaHandler.journeyEngine);
        Spark.post("/journey/build-client-oauth-response", LambdaHandler.buildClientOauthResponse);
        Spark.get(
                "/journey/build-proven-user-identity-details",
                LambdaHandler.buildProvenUserIdentityDetails);
        Spark.post("/journey/cri/callback", LambdaHandler.criCallBack);

        Spark.post("/token", LambdaHandler.token);
        Spark.get("/user-identity", LambdaHandler.userIdentity);

        Spark.internalServerError("🤮");
    }
}
