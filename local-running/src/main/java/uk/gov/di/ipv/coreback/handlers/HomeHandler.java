package uk.gov.di.ipv.coreback.handlers;

import spark.Request;
import spark.Response;
import spark.Route;

public class HomeHandler {
    private HomeHandler() {
        throw new IllegalStateException("Utility class");
    }

    public static final Route serveHomePage = (Request request, Response response) -> "🐧";
}
