package uk.gov.di.ipv.core.callticfcri.service;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import software.amazon.lambda.powertools.tracing.Tracing;
import uk.gov.di.ipv.core.callticfcri.dto.TicfCriDto;
import uk.gov.di.ipv.core.callticfcri.exception.TicfCriHttpResponseException;
import uk.gov.di.ipv.core.callticfcri.exception.TicfCriServiceException;
import uk.gov.di.ipv.core.library.annotations.ExcludeFromGeneratedCoverageReport;
import uk.gov.di.ipv.core.library.domain.VerifiableCredential;
import uk.gov.di.ipv.core.library.domain.VerifiableCredentialConstants;
import uk.gov.di.ipv.core.library.dto.RestCriConfig;
import uk.gov.di.ipv.core.library.exceptions.VerifiableCredentialException;
import uk.gov.di.ipv.core.library.helpers.LogHelper;
import uk.gov.di.ipv.core.library.persistence.item.ClientOAuthSessionItem;
import uk.gov.di.ipv.core.library.persistence.item.IpvSessionItem;
import uk.gov.di.ipv.core.library.service.ConfigService;
import uk.gov.di.ipv.core.library.verifiablecredential.service.SessionCredentialsService;
import uk.gov.di.ipv.core.library.verifiablecredential.validator.VerifiableCredentialValidator;

import java.io.IOException;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.text.ParseException;
import java.util.List;

import static uk.gov.di.ipv.core.library.config.CoreFeatureFlag.SESSION_CREDENTIALS_TABLE_READS;
import static uk.gov.di.ipv.core.library.domain.CriConstants.TICF_CRI;

public class TicfCriService {
    private static final Logger LOGGER = LogManager.getLogger();
    private static final ObjectMapper OBJECT_MAPPER = new ObjectMapper();
    public static final String TRUSTMARK = "https://oidc.account.gov.uk/trustmark";
    public static final String X_API_KEY_HEADER = "x-api-key";

    private final ConfigService configService;
    private final HttpClient httpClient;
    private final VerifiableCredentialValidator jwtValidator;
    private final SessionCredentialsService sessionCredentialsService;

    public TicfCriService(ConfigService configService) {
        this.configService = configService;
        this.httpClient = HttpClient.newHttpClient();
        this.jwtValidator = new VerifiableCredentialValidator(configService);
        this.sessionCredentialsService = new SessionCredentialsService(configService);
    }

    @ExcludeFromGeneratedCoverageReport
    public TicfCriService(
            ConfigService configService,
            VerifiableCredentialValidator jwtValidator,
            SessionCredentialsService sessionCredentialsService) {
        this.configService = configService;
        this.httpClient = HttpClient.newHttpClient();
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

    public List<VerifiableCredential> getTicfVc(
            ClientOAuthSessionItem clientOAuthSessionItem, IpvSessionItem ipvSessionItem)
            throws TicfCriServiceException {
        try {
            RestCriConfig ticfCriConfig = configService.getRestCriConfig(TICF_CRI);

            TicfCriDto ticfCriRequest =
                    new TicfCriDto(
                            clientOAuthSessionItem.getVtr(),
                            ipvSessionItem.getVot(),
                            TRUSTMARK,
                            clientOAuthSessionItem.getUserId(),
                            clientOAuthSessionItem.getGovukSigninJourneyId(),
                            configService.enabled(SESSION_CREDENTIALS_TABLE_READS)
                                    ? sessionCredentialsService
                                            .getCredentials(
                                                    ipvSessionItem.getIpvSessionId(),
                                                    clientOAuthSessionItem.getUserId(),
                                                    true)
                                            .stream()
                                            .map(VerifiableCredential::getVcString)
                                            .toList()
                                    : ipvSessionItem.getVcReceivedThisSession());

            HttpRequest.Builder httpRequestBuilder =
                    HttpRequest.newBuilder()
                            .uri(ticfCriConfig.getCredentialUrl())
                            .POST(
                                    HttpRequest.BodyPublishers.ofString(
                                            OBJECT_MAPPER.writeValueAsString(ticfCriRequest)));
            if (ticfCriConfig.isRequiresApiKey()) {
                httpRequestBuilder.header(
                        X_API_KEY_HEADER,
                        configService.getCriPrivateApiKeyForActiveConnection(TICF_CRI));
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
                    TICF_CRI,
                    ticfCriResponse.credentials(),
                    VerifiableCredentialConstants.IDENTITY_CHECK_CREDENTIAL_TYPE,
                    ticfCriConfig.getParsedSigningKey(),
                    ticfCriConfig.getComponentId());
        } catch (ParseException | VerifiableCredentialException | JsonProcessingException e) {
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
            throw new TicfCriHttpResponseException(
                    String.format(
                            "Non 200 HTTP status code: '%s'", ticfCriHttpResponse.statusCode()));
        }
        LOGGER.info(LogHelper.buildLogMessage("Successful HTTP response from TICF CRI"));
    }

    @Tracing
    private HttpResponse<String> sendHttpRequest(HttpRequest ticfCriHttpRequest)
            throws IOException, InterruptedException {
        LOGGER.info(LogHelper.buildLogMessage("Sending HTTP request to TICF CRI"));
        return httpClient.send(ticfCriHttpRequest, HttpResponse.BodyHandlers.ofString());
    }
}
