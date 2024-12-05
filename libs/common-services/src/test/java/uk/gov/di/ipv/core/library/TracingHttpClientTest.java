package uk.gov.di.ipv.core.library;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import uk.gov.di.ipv.core.library.tracing.TracingHttpClient;

import java.io.IOException;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpHeaders;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.util.Map;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
class TracingHttpClientTest {
    @Mock private HttpClient mockHttpClient;
    @Mock private HttpResponse<Object> mockHttpResponse;
    @InjectMocks private TracingHttpClient tracingHttpClient;

    @Test
    void sendShouldRetryGoawayResponse() throws Exception {
        when(mockHttpClient.send(any(), any()))
                .thenThrow(new IOException("GOAWAY received"))
                .thenReturn(mockHttpResponse);
        when(mockHttpResponse.headers()).thenReturn(HttpHeaders.of(Map.of(), (h, v) -> true));

        tracingHttpClient.send(
                HttpRequest.newBuilder().uri(URI.create("https://example.com")).build(),
                HttpResponse.BodyHandlers.ofString());

        verify(mockHttpClient, times(2)).send(any(), any());
    }

    @Test
    void sendShouldRetryConnectionReset() throws Exception {
        when(mockHttpClient.send(any(), any()))
                .thenThrow(new IOException("Connection reset"))
                .thenReturn(mockHttpResponse);
        when(mockHttpResponse.headers()).thenReturn(HttpHeaders.of(Map.of(), (h, v) -> true));

        tracingHttpClient.send(
                HttpRequest.newBuilder().uri(URI.create("https://example.com")).build(),
                HttpResponse.BodyHandlers.ofString());

        verify(mockHttpClient, times(2)).send(any(), any());
    }
}
