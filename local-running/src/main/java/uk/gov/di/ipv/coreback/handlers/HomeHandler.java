package uk.gov.di.ipv.coreback.handlers;

import spark.Request;
import spark.Response;
import spark.Route;

public class HomeHandler {
    public static Route serveHomePage = (Request request, Response response) -> "🐧";
}
