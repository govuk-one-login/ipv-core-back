package uk.gov.di.ipv.core.buildprovenuseridentitydetails;

import com.amazonaws.services.lambda.runtime.Context;
import com.amazonaws.services.lambda.runtime.RequestHandler;
import com.amazonaws.services.lambda.runtime.events.APIGatewayProxyRequestEvent;
import com.amazonaws.services.lambda.runtime.events.APIGatewayProxyResponseEvent;
import com.nimbusds.oauth2.sdk.http.HTTPResponse;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import software.amazon.lambda.powertools.logging.Logging;
import software.amazon.lambda.powertools.metrics.Metrics;
import uk.gov.di.ipv.core.buildprovenuseridentitydetails.domain.ProvenUserIdentityDetails;
import uk.gov.di.ipv.core.buildprovenuseridentitydetails.exceptions.ProvenUserIdentityDetailsException;
import uk.gov.di.ipv.core.library.annotations.ExcludeFromGeneratedCoverageReport;
import uk.gov.di.ipv.core.library.domain.ErrorResponse;
import uk.gov.di.ipv.core.library.domain.IdentityClaim;
import uk.gov.di.ipv.core.library.domain.VerifiableCredential;
import uk.gov.di.ipv.core.library.exceptions.HttpResponseExceptionWithErrorBody;
import uk.gov.di.ipv.core.library.exceptions.IpvSessionNotFoundException;
import uk.gov.di.ipv.core.library.exceptions.VerifiableCredentialException;
import uk.gov.di.ipv.core.library.helpers.ApiGatewayResponseGenerator;
import uk.gov.di.ipv.core.library.helpers.LogHelper;
import uk.gov.di.ipv.core.library.helpers.RequestHelper;
import uk.gov.di.ipv.core.library.persistence.item.ClientOAuthSessionItem;
import uk.gov.di.ipv.core.library.persistence.item.IpvSessionItem;
import uk.gov.di.ipv.core.library.service.ClientOAuthSessionDetailsService;
import uk.gov.di.ipv.core.library.service.ConfigService;
import uk.gov.di.ipv.core.library.service.IpvSessionService;
import uk.gov.di.ipv.core.library.useridentity.service.UserIdentityService;
import uk.gov.di.ipv.core.library.verifiablecredential.helpers.VcHelper;
import uk.gov.di.ipv.core.library.verifiablecredential.service.SessionCredentialsService;
import uk.gov.di.model.PostalAddress;

import java.io.UncheckedIOException;
import java.util.Comparator;
import java.util.List;
import java.util.Optional;

public class BuildProvenUserIdentityDetailsHandler
        implements RequestHandler<APIGatewayProxyRequestEvent, APIGatewayProxyResponseEvent> {
    private static final Logger LOGGER = LogManager.getLogger();
    private final IpvSessionService ipvSessionService;
    private final UserIdentityService userIdentityService;
    private final ConfigService configService;
    private final ClientOAuthSessionDetailsService clientOAuthSessionDetailsService;
    private final SessionCredentialsService sessionCredentialsService;

    public BuildProvenUserIdentityDetailsHandler(
            IpvSessionService ipvSessionService,
            UserIdentityService userIdentityService,
            ConfigService configService,
            ClientOAuthSessionDetailsService clientOAuthSessionDetailsService,
            SessionCredentialsService sessionCredentialsService) {
        this.ipvSessionService = ipvSessionService;
        this.userIdentityService = userIdentityService;
        this.configService = configService;
        this.clientOAuthSessionDetailsService = clientOAuthSessionDetailsService;
        this.sessionCredentialsService = sessionCredentialsService;
        VcHelper.setConfigService(this.configService);
    }

    @ExcludeFromGeneratedCoverageReport
    public BuildProvenUserIdentityDetailsHandler() {
        this.configService = ConfigService.create();
        this.ipvSessionService = new IpvSessionService(configService);
        this.userIdentityService = new UserIdentityService(configService);
        this.clientOAuthSessionDetailsService = new ClientOAuthSessionDetailsService(configService);
        this.sessionCredentialsService = new SessionCredentialsService(configService);
        VcHelper.setConfigService(this.configService);
    }

    @Override
    @Logging(clearState = true)
    @Metrics(captureColdStart = true)
    public APIGatewayProxyResponseEvent handleRequest(
            APIGatewayProxyRequestEvent input, Context context) {
        LogHelper.attachTraceId();
        LogHelper.attachComponentId(configService);
        ProvenUserIdentityDetails.ProvenUserIdentityDetailsBuilder
                provenUserIdentityDetailsBuilder = ProvenUserIdentityDetails.builder();
        try {
            configService.setFeatureSet(RequestHelper.getFeatureSet(input));
            String ipvSessionId = RequestHelper.getIpvSessionId(input);
            IpvSessionItem ipvSessionItem = ipvSessionService.getIpvSession(ipvSessionId);

            ClientOAuthSessionItem clientOAuthSessionItem =
                    clientOAuthSessionDetailsService.getClientOAuthSession(
                            ipvSessionItem.getClientOAuthSessionId());

            String govukSigninJourneyId = clientOAuthSessionItem.getGovukSigninJourneyId();
            LogHelper.attachGovukSigninJourneyIdToLogs(govukSigninJourneyId);

            var vcs =
                    sessionCredentialsService.getCredentials(
                            ipvSessionId, clientOAuthSessionItem.getUserId());

            var identity = getProvenIdentity(vcs);
            provenUserIdentityDetailsBuilder.name(identity.getFullName());
            provenUserIdentityDetailsBuilder.nameParts(identity.getNameParts());
            provenUserIdentityDetailsBuilder.dateOfBirth(identity.getBirthDate().get(0).getValue());

            var addresses = getProvenIdentityAddresses(vcs);
            provenUserIdentityDetailsBuilder.addresses(addresses);

            LOGGER.info(
                    LogHelper.buildLogMessage("Successfully retrieved proven identity response."));

            return ApiGatewayResponseGenerator.proxyJsonResponse(
                    HTTPResponse.SC_OK, provenUserIdentityDetailsBuilder.build());
        } catch (HttpResponseExceptionWithErrorBody | VerifiableCredentialException e) {
            return buildJourneyErrorResponse(e.getErrorResponse(), e.getResponseCode());
        } catch (ProvenUserIdentityDetailsException e) {
            return buildJourneyErrorResponse(
                    ErrorResponse.FAILED_TO_GENERATE_PROVEN_USER_IDENTITY_DETAILS);
        } catch (IpvSessionNotFoundException e) {
            return buildJourneyErrorResponse(ErrorResponse.IPV_SESSION_NOT_FOUND);
        } catch (UncheckedIOException e) {
            // Temporary mitigation to force lambda instance to crash and restart by explicitly
            // exiting the program on fatal IOException - see PYIC-8220 and incident INC0014398.
            LOGGER.error("Crashing on UncheckedIOException", e);
            System.exit(1);
            return null;
        } catch (Exception e) {
            LOGGER.error(LogHelper.buildErrorMessage("Unhandled lambda exception", e));
            throw e;
        }
    }

    private APIGatewayProxyResponseEvent buildJourneyErrorResponse(ErrorResponse errorResponse) {
        return buildJourneyErrorResponse(errorResponse, 500);
    }

    private APIGatewayProxyResponseEvent buildJourneyErrorResponse(
            ErrorResponse errorResponse, int statusCode) {
        LOGGER.error(LogHelper.buildLogMessage(errorResponse.getMessage()));
        return ApiGatewayResponseGenerator.proxyJsonResponse(statusCode, errorResponse);
    }

    private IdentityClaim getProvenIdentity(List<VerifiableCredential> vcs)
            throws ProvenUserIdentityDetailsException {
        try {
            final Optional<IdentityClaim> identityClaim =
                    userIdentityService.findIdentityClaim(vcs);

            if (identityClaim.isEmpty()) {
                LOGGER.error(LogHelper.buildLogMessage("Failed to generate identity claim"));
                throw new HttpResponseExceptionWithErrorBody(
                        500, ErrorResponse.FAILED_TO_GENERATE_IDENTITY_CLAIM);
            }

            return identityClaim.get();

        } catch (HttpResponseExceptionWithErrorBody e) {
            LOGGER.error(
                    LogHelper.buildLogMessage(
                            "Failed to find name and date of birth of proven user identity"));
            throw new ProvenUserIdentityDetailsException(
                    "Failed to find name and date of birth of proven user identity");
        }
    }

    private List<PostalAddress> getProvenIdentityAddresses(List<VerifiableCredential> vcs)
            throws HttpResponseExceptionWithErrorBody, ProvenUserIdentityDetailsException {
        var addressClaim = userIdentityService.getAddressClaim(vcs);

        if (addressClaim.isEmpty()) {
            LOGGER.error(
                    LogHelper.buildLogMessage("Failed to find addresses of proven user identity"));
            throw new ProvenUserIdentityDetailsException(
                    "Failed to find addresses of proven user identity");
        }

        return addressClaim.get().stream()
                .sorted(
                        Comparator.comparing(
                                PostalAddress::getValidUntil,
                                Comparator.nullsFirst(Comparator.reverseOrder())))
                .toList();
    }
}
