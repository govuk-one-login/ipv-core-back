package uk.gov.di.ipv.core.library.ais.client;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.Captor;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import uk.gov.di.ipv.core.library.ais.exception.AisClientException;
import uk.gov.di.ipv.core.library.config.domain.AisConfig;
import uk.gov.di.ipv.core.library.config.domain.Config;
import uk.gov.di.ipv.core.library.retry.Sleeper;
import uk.gov.di.ipv.core.library.service.ConfigService;

import java.io.IOException;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;

import static com.nimbusds.oauth2.sdk.http.HTTPResponse.SC_NOT_FOUND;
import static com.nimbusds.oauth2.sdk.http.HTTPResponse.SC_OK;
import static com.nimbusds.oauth2.sdk.http.HTTPResponse.SC_SERVER_ERROR;
import static org.assertj.core.api.Assertions.assertThat;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;
import static uk.gov.di.ipv.core.library.ais.TestData.AIS_NO_INTERVENTION_DTO;
import static uk.gov.di.ipv.core.library.ais.TestData.AIS_REPROVE_IDENTITY_DTO;
import static uk.gov.di.ipv.core.library.ais.TestData.AIS_RESPONSE_NO_INTERVENTION;
import static uk.gov.di.ipv.core.library.ais.TestData.AIS_RESPONSE_REPROVE_IDENTITY;

@ExtendWith(MockitoExtension.class)
class AisClientTest {

    private static final String TEST_BASE_URL = "https://example.com";
    private static final String TEST_USER_ID = "testUserId";
    private static final String AIS_ENDPOINT_URL = TEST_BASE_URL + "/ais/" + TEST_USER_ID;
    private static final String AIS_RESPONSE_INVALID = "{'message': 'test message'}";

    @Mock HttpClient httpClient;
    @Captor private ArgumentCaptor<HttpRequest> httpRequestArgumentCaptor;
    @Mock ConfigService configService;
    @Mock Config mockConfig;
    @Mock Sleeper sleeper;
    AisClient underTest;
    @Mock AisConfig mockAis;

    @BeforeEach
    void setUp() {
        when(configService.getConfiguration()).thenReturn(mockConfig);
        when(mockConfig.getAis()).thenReturn(mockAis);
        when(mockAis.getApiBaseUrl()).thenReturn(URI.create(TEST_BASE_URL));

        underTest = new AisClient(configService, httpClient, sleeper);
    }

    @Test
    void getAccountInterventionStatus_whenCalledForAValidUser_returnsDetails()
            throws IOException, InterruptedException, AisClientException {
        // Arrange
        HttpResponse<String> aisResponse = mock(HttpResponse.class);
        when(aisResponse.body()).thenReturn(AIS_RESPONSE_NO_INTERVENTION);
        when(aisResponse.statusCode()).thenReturn(SC_OK);
        when(httpClient.send(any(), any(HttpResponse.BodyHandlers.ofString().getClass())))
                .thenReturn(aisResponse);

        // Act
        var result = underTest.getAccountInterventionStatus(TEST_USER_ID);

        // Assert
        assertThat(result).isEqualToComparingFieldByFieldRecursively(AIS_NO_INTERVENTION_DTO);
    }

    @Test
    void
            getAccountInterventionStatus_whenCalledForAUserNeedingToRepoveTheirIdentity_returnsDetails()
                    throws IOException, InterruptedException, AisClientException {
        // Arrange
        HttpResponse<String> aisResponse = mock(HttpResponse.class);
        when(aisResponse.body()).thenReturn(AIS_RESPONSE_REPROVE_IDENTITY);
        when(aisResponse.statusCode()).thenReturn(SC_OK);
        when(httpClient.send(any(), any(HttpResponse.BodyHandlers.ofString().getClass())))
                .thenReturn(aisResponse);

        // Act
        var result = underTest.getAccountInterventionStatus(TEST_USER_ID);

        // Assert
        assertThat(result).isEqualToComparingFieldByFieldRecursively(AIS_REPROVE_IDENTITY_DTO);
    }

    @Test
    void getAccountInterventionStatus_whenCalledForAValidUser_usesTheCorrectUrl()
            throws IOException, InterruptedException, AisClientException {
        // Arrange
        HttpResponse<String> aisResponse = mock(HttpResponse.class);
        when(aisResponse.body()).thenReturn(AIS_RESPONSE_NO_INTERVENTION);
        when(aisResponse.statusCode()).thenReturn(SC_OK);
        when(httpClient.send(any(), any(HttpResponse.BodyHandlers.ofString().getClass())))
                .thenReturn(aisResponse);

        // Act
        underTest.getAccountInterventionStatus(TEST_USER_ID);

        // Assert
        verify(httpClient).send(httpRequestArgumentCaptor.capture(), any());
        assertThat(httpRequestArgumentCaptor.getValue().uri()).hasToString(AIS_ENDPOINT_URL);
    }

    @Test
    void getAccountInterventionStatus_whenCalledForAValidUser_retriesAisErrors()
            throws IOException, InterruptedException, AisClientException {
        // Arrange
        HttpResponse<String> badAisResponse = mock(HttpResponse.class);
        when(badAisResponse.body()).thenReturn(AIS_RESPONSE_INVALID);
        when(badAisResponse.statusCode()).thenReturn(SC_SERVER_ERROR);
        HttpResponse<String> goodAisResponse = mock(HttpResponse.class);
        when(goodAisResponse.body()).thenReturn(AIS_RESPONSE_NO_INTERVENTION);
        when(goodAisResponse.statusCode()).thenReturn(SC_OK);
        when(httpClient.send(any(), any(HttpResponse.BodyHandlers.ofString().getClass())))
                .thenReturn(badAisResponse, badAisResponse, badAisResponse, goodAisResponse);

        // Act
        var result = underTest.getAccountInterventionStatus(TEST_USER_ID);

        // Assert
        assertThat(result).isEqualToComparingFieldByFieldRecursively(AIS_NO_INTERVENTION_DTO);
        verify(httpClient, times(4)).send(any(), any());
    }

    @Test
    void getAccountInterventionStatus_whenCalledForAValidUser_doesntRetryIoExceptions()
            throws IOException, InterruptedException {
        // Arrange
        HttpResponse<String> goodAisResponse = mock(HttpResponse.class);
        when(httpClient.send(any(), any(HttpResponse.BodyHandlers.ofString().getClass())))
                .thenThrow(new IOException("test"))
                .thenReturn(goodAisResponse);

        // Act & Assert
        assertThrows(
                AisClientException.class,
                () -> underTest.getAccountInterventionStatus(TEST_USER_ID));

        verify(httpClient, times(1)).send(any(), any());
    }

    @Test
    void getAccountInterventionStatus_whenAisReturnsABadResponse_doesntRetryFatalAisErrors()
            throws IOException, InterruptedException {
        // Arrange
        HttpResponse<String> badAisResponse = mock(HttpResponse.class);
        when(badAisResponse.body()).thenReturn(AIS_RESPONSE_INVALID);
        when(badAisResponse.statusCode()).thenReturn(SC_NOT_FOUND);
        when(httpClient.send(any(), any(HttpResponse.BodyHandlers.ofString().getClass())))
                .thenReturn(badAisResponse);

        // Act & Assert
        assertThrows(
                AisClientException.class,
                () -> underTest.getAccountInterventionStatus(TEST_USER_ID));

        verify(httpClient, times(1)).send(any(), any());
    }

    @Test
    void getAccountInterventionStatus_whenAisReturnsABadResponse_throwsAisClientException()
            throws IOException, InterruptedException {
        // Arrange
        HttpResponse<String> aisResponse = mock(HttpResponse.class);
        when(aisResponse.body()).thenReturn(AIS_RESPONSE_INVALID);
        when(aisResponse.statusCode()).thenReturn(SC_OK);
        when(httpClient.send(any(), any(HttpResponse.BodyHandlers.ofString().getClass())))
                .thenReturn(aisResponse);

        // Act & Assert
        assertThrows(
                AisClientException.class,
                () -> underTest.getAccountInterventionStatus(TEST_USER_ID));
    }
}
