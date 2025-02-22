package uk.gov.di.ipv.core.library.tracing;

import com.amazonaws.xray.AWSXRay;
import com.amazonaws.xray.AWSXRayRecorder;
import com.amazonaws.xray.entities.Namespace;
import com.amazonaws.xray.entities.Subsegment;
import io.opentelemetry.api.GlobalOpenTelemetry;
import io.opentelemetry.instrumentation.httpclient.JavaHttpClientTelemetry;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import uk.gov.di.ipv.core.library.annotations.ExcludeFromGeneratedCoverageReport;
import uk.gov.di.ipv.core.library.helpers.LogHelper;

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
import java.time.Instant;
import java.util.HashMap;
import java.util.Map;
import java.util.Optional;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.Executor;

// Implementation of java.net.HttpClient that includes AWS X-Ray tracing
@ExcludeFromGeneratedCoverageReport
public class TracingHttpClient extends HttpClient {
    private static final Logger LOGGER = LogManager.getLogger();
    private static final Duration MAX_CLIENT_AGE = Duration.ofHours(1);
    private HttpClient baseClient;
    private final AWSXRayRecorder recorder;
    private Instant creationTime;

    private TracingHttpClient(HttpClient baseClient) {
        this.baseClient = baseClient;
        this.recorder = AWSXRay.getGlobalRecorder();
        this.creationTime = Instant.now();
    }

    public static HttpClient newHttpClient() {
        return new TracingHttpClient(getOTelInstrumentedHttpClient());
    }

    @Override
    public <T> HttpResponse<T> send(
            HttpRequest request, HttpResponse.BodyHandler<T> responseBodyHandler)
            throws IOException, InterruptedException {
        // PYIC-7590: Recreate the HTTP client, to avoid HTTP/2 connection issues.
        // Check for client is 1hour old, and recreate if older.
        recreateBaseClientIfNecessary();
        try {
            return sendWithTracing(request, responseBodyHandler);
        } catch (IOException e) {
            // In the build environment we see connection resets for idle connections in
            // the pool. Retrying uses a different connection.
            if (e.getMessage().contains("Connection reset")) {
                LOGGER.warn(
                        LogHelper.buildErrorMessage("Retrying after HTTP IOException", e)
                                .with("host", request.uri().getHost()));
                return sendWithTracing(request, responseBodyHandler);
            }
            throw e;
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

    // Synchronize to prevent race conditions when multiple threads attempt to recreate client
    private synchronized void recreateBaseClientIfNecessary() {
        if (creationTime.plus(MAX_CLIENT_AGE).isBefore(Instant.now())) {
            LOGGER.info("Recreating base HTTP client due to age");
            this.baseClient = getOTelInstrumentedHttpClient();
            this.creationTime = Instant.now(); // Reset creation time
        }
    }

    private <T> HttpResponse<T> sendWithTracing(
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

    private static HttpClient getOTelInstrumentedHttpClient() {
        return JavaHttpClientTelemetry.builder(GlobalOpenTelemetry.get())
                .build()
                .newHttpClient(HttpClient.newHttpClient());
    }
}
