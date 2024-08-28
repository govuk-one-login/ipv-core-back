package uk.gov.di.ipv.core.library.tracing;

import com.amazonaws.xray.AWSXRay;
import com.amazonaws.xray.AWSXRayRecorder;
import com.amazonaws.xray.entities.Namespace;
import com.amazonaws.xray.entities.Subsegment;
import uk.gov.di.ipv.core.library.annotations.ExcludeFromGeneratedCoverageReport;

import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLParameters;

import java.io.IOException;
import java.net.Authenticator;
import java.net.CookieHandler;
import java.net.ProxySelector;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.time.Duration;
import java.util.HashMap;
import java.util.Map;
import java.util.Optional;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.Executor;

// Implementation of java.net.HttpClient that includes AWS X-Ray tracing
@ExcludeFromGeneratedCoverageReport
public class TracingHttpClient extends HttpClient {
    private final HttpClient baseClient;
    private final AWSXRayRecorder recorder;

    private TracingHttpClient(HttpClient baseClient) {
        this.baseClient = baseClient;
        this.recorder = AWSXRay.getGlobalRecorder();
    }

    public static HttpClient newHttpClient() {
        return new TracingHttpClient(HttpClient.newHttpClient());
    }

    @Override
    public Optional<CookieHandler> cookieHandler() {
        return baseClient.cookieHandler();
    }

    @Override
    public Optional<Duration> connectTimeout() {
        return baseClient.connectTimeout();
    }

    @Override
    public Redirect followRedirects() {
        return baseClient.followRedirects();
    }

    @Override
    public Optional<ProxySelector> proxy() {
        return baseClient.proxy();
    }

    @Override
    public SSLContext sslContext() {
        return baseClient.sslContext();
    }

    @Override
    public SSLParameters sslParameters() {
        return baseClient.sslParameters();
    }

    @Override
    public Optional<Authenticator> authenticator() {
        return baseClient.authenticator();
    }

    @Override
    public Version version() {
        return baseClient.version();
    }

    @Override
    public Optional<Executor> executor() {
        return baseClient.executor();
    }

    @Override
    public <T> HttpResponse<T> send(
            HttpRequest request, HttpResponse.BodyHandler<T> responseBodyHandler)
            throws IOException, InterruptedException {
        var subsegment = recorder.beginSubsegment(request.uri().getHost());
        addRequestInformation(subsegment, request);
        try {
            return baseClient.send(
                    request, new TracingResponseHandler<>(subsegment, responseBodyHandler));
        } catch (Exception e) {
            subsegment.addException(e);
            throw e;
        } finally {
            recorder.endSubsegment();
        }
    }

    @Override
    public <T> CompletableFuture<HttpResponse<T>> sendAsync(
            HttpRequest request, HttpResponse.BodyHandler<T> responseBodyHandler) {
        throw new UnsupportedOperationException(
                "TracingHttpClient does not support async requests yet");
    }

    @Override
    public <T> CompletableFuture<HttpResponse<T>> sendAsync(
            HttpRequest request,
            HttpResponse.BodyHandler<T> responseBodyHandler,
            HttpResponse.PushPromiseHandler<T> pushPromiseHandler) {
        throw new UnsupportedOperationException(
                "TracingHttpClient does not support async requests yet");
    }

    // Adapted from
    // https://github.com/aws/aws-xray-sdk-java/blob/master/aws-xray-recorder-sdk-apache-http/src/main/java/com/amazonaws/xray/proxies/apache/http/TracedHttpClient.java#L103
    private static void addRequestInformation(Subsegment subsegment, HttpRequest request) {
        subsegment.setNamespace(Namespace.REMOTE.toString());

        Map<String, Object> requestInformation = new HashMap<>();

        // Resolve against `/` to strip any sensitive data from the path
        requestInformation.put("url", request.uri().resolve("/").toString());
        requestInformation.put("method", request.method());

        subsegment.putHttp("request", requestInformation);
    }
}
