package uk.gov.di.ipv.core.calldcmawasynccri.service;

import com.fasterxml.jackson.core.JsonProcessingException;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import software.amazon.lambda.powertools.tracing.Tracing;
import uk.gov.di.ipv.core.library.annotations.ExcludeFromGeneratedCoverageReport;
import uk.gov.di.ipv.core.library.criapiservice.CriApiService;
import uk.gov.di.ipv.core.library.criapiservice.dto.CredentialRequestBodyDto;
import uk.gov.di.ipv.core.library.criapiservice.exception.CriApiException;
import uk.gov.di.ipv.core.library.helpers.LogHelper;
import uk.gov.di.ipv.core.library.helpers.SecureTokenHelper;
import uk.gov.di.ipv.core.library.kmses256signer.KmsEs256SignerFactory;
import uk.gov.di.ipv.core.library.persistence.item.ClientOAuthSessionItem;
import uk.gov.di.ipv.core.library.persistence.item.CriOAuthSessionItem;
import uk.gov.di.ipv.core.library.persistence.item.IpvSessionItem;
import uk.gov.di.ipv.core.library.service.ConfigService;
import uk.gov.di.ipv.core.library.verifiablecredential.domain.VerifiableCredentialResponse;

import java.io.IOException;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.time.Clock;

import static uk.gov.di.ipv.core.library.domain.CriConstants.DCMAW_ASYNC_CRI;

public class DcmawAsyncCriService {
    private static final Logger LOGGER = LogManager.getLogger();

    private final ConfigService configService;
    private final HttpClient httpClient;
    private final CriApiService criApiService;

    public DcmawAsyncCriService(ConfigService configService) {
        this.configService = configService;
        this.httpClient = HttpClient.newHttpClient();
        this.criApiService =
                new CriApiService(
                        configService,
                        new KmsEs256SignerFactory(),
                        SecureTokenHelper.getInstance(),
                        Clock.systemDefaultZone());
    }

    @ExcludeFromGeneratedCoverageReport
    public DcmawAsyncCriService(ConfigService configService, CriApiService criApiService) {
        this.configService = configService;
        this.httpClient = HttpClient.newHttpClient();
        this.criApiService = criApiService;
    }

    public VerifiableCredentialResponse startDcmawAsyncSession(
            String oauthState,
            ClientOAuthSessionItem clientOAuthSessionItem,
            IpvSessionItem ipvSessionItem)
            throws CriApiException, JsonProcessingException {
        // qq:DCC
        final String criId = DCMAW_ASYNC_CRI;
        String connection = configService.getActiveConnection(criId);

        // qq:DCC this is what BuildCriOAuthRequestHandler does to generate and store a
        // CriOAuthSessionItem
        // Do we need to do all this here?

        //        ipvSessionItem.setCriOAuthSessionId(oauthState); // This seems to just be used to
        // retrieve the CriOAuthSessionItem from the criOAuthSessionService
        //        ipvSessionService.updateIpvSession(ipvSessionItem);
        //        var criOAuthDetails = criOAuthSessionService.persistCriOAuthSession(
        //                oauthState, criId, clientOAuthSessionItem.getClientOAuthSessionId(),
        // connection);

        CriOAuthSessionItem criOAuthSessionItem =
                CriOAuthSessionItem.builder()
                        .criOAuthSessionId(oauthState)
                        .criId(criId)
                        .clientOAuthSessionId(clientOAuthSessionItem.getClientOAuthSessionId())
                        .connection(connection)
                        .build();

        String dcmawAsyncClientSecret = configService.getCriOAuthClientSecret(criOAuthSessionItem);
        var criConfig = configService.getOauthCriConfig(criOAuthSessionItem);

        var accessToken =
                criApiService.fetchAccessToken(criConfig.getClientId(), dcmawAsyncClientSecret, criOAuthSessionItem);

        var credentialRequestBody =
                new CredentialRequestBodyDto(
                        clientOAuthSessionItem.getUserId(),
                        clientOAuthSessionItem.getGovukSigninJourneyId(),
                        criConfig.getClientId(),
                        oauthState,
                        criConfig.getClientCallbackUrl().toString());

        var vcResponse =
                criApiService.fetchVerifiableCredential(
                        accessToken, criId, criOAuthSessionItem, credentialRequestBody);

        return vcResponse;
    }

    @Tracing
    private HttpResponse<String> sendHttpRequest(HttpRequest ticfCriHttpRequest)
            throws IOException, InterruptedException {
        LOGGER.info(LogHelper.buildLogMessage("Sending HTTP request to TICF CRI"));
        return httpClient.send(ticfCriHttpRequest, HttpResponse.BodyHandlers.ofString());
    }
}
