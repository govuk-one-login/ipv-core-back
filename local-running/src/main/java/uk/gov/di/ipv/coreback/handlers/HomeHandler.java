package uk.gov.di.ipv.coreback.handlers;

import io.javalin.http.Context;

public class HomeHandler {
    private HomeHandler() {
        throw new IllegalStateException("Utility class");
    }

    public static void serveHomePage(Context ctx) {
        ctx.result("IPV Core Back local-running");
    }
}
