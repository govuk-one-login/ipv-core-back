package uk.gov.di.ipv.core.library.tracing;

import io.opentelemetry.api.GlobalOpenTelemetry;
import io.opentelemetry.instrumentation.javahttpclient.JavaHttpClientTelemetry;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import uk.gov.di.ipv.core.library.annotations.ExcludeFromGeneratedCoverageReport;
import uk.gov.di.ipv.core.library.helpers.LogHelper;

import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLParameters;

import java.io.IOException;
import java.io.UncheckedIOException;
import java.net.Authenticator;
import java.net.CookieHandler;
import java.net.HttpRetryException;
import java.net.ProxySelector;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.net.http.HttpTimeoutException;
import java.time.Duration;
import java.time.Instant;
import java.util.Optional;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.Executor;

// Implementation of java.net.HttpClient that includes OpenTelemetry tracing and additional error
// handling
@ExcludeFromGeneratedCoverageReport
public class TracingHttpClient extends HttpClient {
    private static final Logger LOGGER = LogManager.getLogger();
    private static final Duration MAX_CLIENT_AGE = Duration.ofHours(1);
    private HttpClient baseClient;
    private Instant creationTime;

    private TracingHttpClient(HttpClient baseClient) {
        this.baseClient = baseClient;
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
            return baseClient.send(request, responseBodyHandler);
        } catch (IOException e) {
            if (e instanceof HttpTimeoutException) {
                LOGGER.warn(LogHelper.buildErrorMessage("HTTP request timed out", e));
                throw e;
            }
            // We occasionally see HTTP/2 GOAWAY messages and in build we occasionally see
            // connection resets for idle connections in the pool. Retrying uses a different
            // connection.
            if ((e.getMessage() != null
                            && (e.getMessage().contains("GOAWAY received")
                                    || e.getMessage().contains("Connection reset")))
                    || e instanceof HttpRetryException) {
                LOGGER.warn(
                        LogHelper.buildErrorMessage("Retrying after non-fatal HTTP IOException", e)
                                .with("host", request.uri().getHost()));
                try {
                    return baseClient.send(request, responseBodyHandler);
                } catch (IOException ex) {
                    throw new UncheckedIOException(ex);
                }
            }
            LOGGER.error(LogHelper.buildErrorMessage("HTTP request failed with IOException", e));
            // Rethrow any other IOException as unchecked exception
            throw new UncheckedIOException(e);
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

    private static HttpClient getOTelInstrumentedHttpClient() {
        return JavaHttpClientTelemetry.builder(GlobalOpenTelemetry.get())
                .build()
                .newHttpClient(HttpClient.newHttpClient());
    }
}
