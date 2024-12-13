package uk.gov.di.ipv.core.processcandidateidentity.service;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import software.amazon.lambda.powertools.tracing.Tracing;
import uk.gov.di.ipv.core.library.annotations.ExcludeFromGeneratedCoverageReport;
import uk.gov.di.ipv.core.library.config.ConfigurationVariable;
import uk.gov.di.ipv.core.library.domain.ErrorResponse;
import uk.gov.di.ipv.core.library.domain.VerifiableCredential;
import uk.gov.di.ipv.core.library.exceptions.VerifiableCredentialException;
import uk.gov.di.ipv.core.library.helpers.LogHelper;
import uk.gov.di.ipv.core.library.persistence.item.ClientOAuthSessionItem;
import uk.gov.di.ipv.core.library.persistence.item.IpvSessionItem;
import uk.gov.di.ipv.core.library.service.ConfigService;
import uk.gov.di.ipv.core.library.tracing.TracingHttpClient;
import uk.gov.di.ipv.core.library.verifiablecredential.service.SessionCredentialsService;
import uk.gov.di.ipv.core.library.verifiablecredential.validator.VerifiableCredentialValidator;
import uk.gov.di.ipv.core.processcandidateidentity.dto.TicfCriDto;
import uk.gov.di.ipv.core.processcandidateidentity.exception.TicfCriHttpResponseException;
import uk.gov.di.ipv.core.processcandidateidentity.exception.TicfCriServiceException;

import java.io.IOException;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.net.http.HttpTimeoutException;
import java.time.Duration;
import java.util.List;

import static uk.gov.di.ipv.core.library.domain.Cri.TICF;
import static uk.gov.di.ipv.core.library.helpers.LogHelper.LogField.LOG_STATUS_CODE;

@SuppressWarnings("java:S107") // Should allow duplicate code for now
public class TicfCriService {
    private static final Logger LOGGER = LogManager.getLogger();
    private static final ObjectMapper OBJECT_MAPPER = new ObjectMapper();
    public static final String TRUSTMARK = "https://oidc.account.gov.uk/trustmark";
    public static final String X_API_KEY_HEADER = "x-api-key";

    private final ConfigService configService;
    private final HttpClient httpClient;
    private final VerifiableCredentialValidator jwtValidator;
    private final SessionCredentialsService sessionCredentialsService;

    @ExcludeFromGeneratedCoverageReport
    public TicfCriService(ConfigService configService) {
        this.configService = configService;
        this.httpClient = TracingHttpClient.newHttpClient();
        this.jwtValidator = new VerifiableCredentialValidator(configService);
        this.sessionCredentialsService = new SessionCredentialsService(configService);
    }

    // Used by contract tests
    @ExcludeFromGeneratedCoverageReport
    public TicfCriService(
            ConfigService configService,
            VerifiableCredentialValidator jwtValidator,
            SessionCredentialsService sessionCredentialsService) {
        this.configService = configService;
        this.httpClient = TracingHttpClient.newHttpClient();
        this.jwtValidator = jwtValidator;
        this.sessionCredentialsService = sessionCredentialsService;
    }

    protected TicfCriService(
            ConfigService configService,
            HttpClient httpClient,
            VerifiableCredentialValidator jwtValidator,
            SessionCredentialsService sessionCredentialsService) {
        this.configService = configService;
        this.httpClient = httpClient;
        this.jwtValidator = jwtValidator;
        this.sessionCredentialsService = sessionCredentialsService;
    }

    @Tracing
    public List<VerifiableCredential> getTicfVc(
            ClientOAuthSessionItem clientOAuthSessionItem, IpvSessionItem ipvSessionItem)
            throws TicfCriServiceException {
        try {
            var connection = configService.getActiveConnection(TICF);
            var ticfCriConfig = configService.getRestCriConfigForConnection(connection, TICF);

            var ticfCriRequest =
                    new TicfCriDto(
                            clientOAuthSessionItem.getVtr(),
                            ipvSessionItem.getVot(),
                            TRUSTMARK,
                            clientOAuthSessionItem.getUserId(),
                            clientOAuthSessionItem.getGovukSigninJourneyId(),
                            sessionCredentialsService
                                    .getCredentials(
                                            ipvSessionItem.getIpvSessionId(),
                                            clientOAuthSessionItem.getUserId(),
                                            true)
                                    .stream()
                                    .map(VerifiableCredential::getVcString)
                                    .toList());

            var httpRequestBuilder =
                    HttpRequest.newBuilder()
                            .uri(ticfCriConfig.getCredentialUrl())
                            .timeout(Duration.ofSeconds(ticfCriConfig.getRequestTimeout()))
                            .POST(
                                    HttpRequest.BodyPublishers.ofString(
                                            OBJECT_MAPPER.writeValueAsString(ticfCriRequest)));
            if (ticfCriConfig.isRequiresApiKey()) {
                httpRequestBuilder.header(
                        X_API_KEY_HEADER,
                        configService.getSecret(
                                ConfigurationVariable.CREDENTIAL_ISSUER_API_KEY,
                                TICF.getId(),
                                connection));
            }
            httpRequestBuilder.header("Content-Type", "application/json; charset=utf-8");

            var ticfCriHttpResponse = sendHttpRequest(httpRequestBuilder.build());
            checkStatusCode(ticfCriHttpResponse);

            TicfCriDto ticfCriResponse =
                    OBJECT_MAPPER.readValue(ticfCriHttpResponse.body(), TicfCriDto.class);

            if (ticfCriResponse.credentials().isEmpty()) {
                throw new TicfCriServiceException("No credentials in TICF CRI response");
            }

            return jwtValidator.parseAndValidate(
                    clientOAuthSessionItem.getUserId(),
                    TICF,
                    ticfCriResponse.credentials(),
                    ticfCriConfig.getSigningKey(),
                    ticfCriConfig.getComponentId());
        } catch (VerifiableCredentialException | JsonProcessingException e) {
            throw new TicfCriServiceException(e);
        } catch (IOException
                | InterruptedException
                | IllegalArgumentException
                | SecurityException
                | TicfCriHttpResponseException e) {
            if (e instanceof InterruptedException) {
                // This should never happen running in Lambda as it's single threaded.
                Thread.currentThread().interrupt();
            }

            if (e instanceof HttpTimeoutException) {
                LOGGER.warn(LogHelper.buildLogMessage("Request to TICF CRI has timed out"));
            }
            // In the case of unavailability, the TICF CRI is deemed optional.
            LOGGER.error(
                    LogHelper.buildErrorMessage(
                            "Request to TICF CRI failed. Allowing user journey to continue", e));
            return List.of();
        }
    }

    private void checkStatusCode(HttpResponse<String> ticfCriHttpResponse)
            throws TicfCriHttpResponseException {
        if (200 > ticfCriHttpResponse.statusCode() || ticfCriHttpResponse.statusCode() > 299) {
            LOGGER.info(
                    LogHelper.buildLogMessage(
                                    ErrorResponse.RECEIVED_NON_200_RESPONSE_STATUS_CODE
                                            .getMessage())
                            .with(
                                    LOG_STATUS_CODE.getFieldName(),
                                    ticfCriHttpResponse.statusCode()));
            throw new TicfCriHttpResponseException(
                    String.format(
                            "Non 200 HTTP status code: '%s'", ticfCriHttpResponse.statusCode()));
        }
        LOGGER.info(LogHelper.buildLogMessage("Successful HTTP response from TICF CRI"));
    }

    private HttpResponse<String> sendHttpRequest(HttpRequest ticfCriHttpRequest)
            throws IOException, InterruptedException {
        LOGGER.info(LogHelper.buildLogMessage("Sending HTTP request to TICF CRI"));
        return httpClient.send(ticfCriHttpRequest, HttpResponse.BodyHandlers.ofString());
    }
}
