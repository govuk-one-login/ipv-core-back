package uk.gov.di.ipv.core.library.tracing;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import java.io.IOException;
import java.io.UncheckedIOException;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.net.http.HttpTimeoutException;

import static org.junit.jupiter.api.Assertions.assertThrowsExactly;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
class TracingHttpClientTest {
    @Mock private HttpClient mockHttpClient;
    @InjectMocks private TracingHttpClient tracingHttpClient;

    @Test
    void sendShouldRetryConnectionReset() throws Exception {
        when(mockHttpClient.send(any(), any()))
                .thenThrow(new IOException("Connection reset"))
                .thenReturn(null);

        tracingHttpClient.send(
                HttpRequest.newBuilder().uri(URI.create("https://example.com")).build(),
                HttpResponse.BodyHandlers.ofString());

        verify(mockHttpClient, times(2)).send(any(), any());
    }

    @Test
    void sendShouldRethrowIfTimeoutException() throws Exception {
        when(mockHttpClient.send(any(), any()))
                .thenThrow(new HttpTimeoutException("Timed out"))
                .thenReturn(null);
        var req = HttpRequest.newBuilder().uri(URI.create("https://example.com")).build();
        var handler = HttpResponse.BodyHandlers.ofString();

        assertThrowsExactly(HttpTimeoutException.class, () -> tracingHttpClient.send(req, handler));
    }

    @Test
    void sendShouldThrowUncheckedExceptionIfFatalIOException() throws Exception {
        when(mockHttpClient.send(any(), any()))
                .thenThrow(new IOException("Something fatal"))
                .thenReturn(null);
        var req = HttpRequest.newBuilder().uri(URI.create("https://example.com")).build();
        var handler = HttpResponse.BodyHandlers.ofString();

        assertThrowsExactly(UncheckedIOException.class, () -> tracingHttpClient.send(req, handler));
    }
}
