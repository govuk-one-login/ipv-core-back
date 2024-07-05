package uk.gov.di.ipv.core.buildprovenuseridentitydetails;

import com.amazonaws.services.lambda.runtime.Context;
import com.amazonaws.services.lambda.runtime.RequestHandler;
import com.amazonaws.services.lambda.runtime.events.APIGatewayProxyRequestEvent;
import com.amazonaws.services.lambda.runtime.events.APIGatewayProxyResponseEvent;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.nimbusds.jwt.SignedJWT;
import com.nimbusds.oauth2.sdk.http.HTTPResponse;
import org.apache.http.HttpStatus;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import software.amazon.lambda.powertools.logging.Logging;
import software.amazon.lambda.powertools.tracing.Tracing;
import uk.gov.di.ipv.core.buildprovenuseridentitydetails.domain.ProvenUserIdentityDetails;
import uk.gov.di.ipv.core.buildprovenuseridentitydetails.exceptions.ProvenUserIdentityDetailsException;
import uk.gov.di.ipv.core.library.annotations.ExcludeFromGeneratedCoverageReport;
import uk.gov.di.ipv.core.library.domain.Address;
import uk.gov.di.ipv.core.library.domain.ErrorResponse;
import uk.gov.di.ipv.core.library.domain.IdentityClaim;
import uk.gov.di.ipv.core.library.domain.ProfileType;
import uk.gov.di.ipv.core.library.domain.VerifiableCredential;
import uk.gov.di.ipv.core.library.exceptions.CredentialParseException;
import uk.gov.di.ipv.core.library.exceptions.HttpResponseExceptionWithErrorBody;
import uk.gov.di.ipv.core.library.exceptions.VerifiableCredentialException;
import uk.gov.di.ipv.core.library.helpers.ApiGatewayResponseGenerator;
import uk.gov.di.ipv.core.library.helpers.LogHelper;
import uk.gov.di.ipv.core.library.helpers.RequestHelper;
import uk.gov.di.ipv.core.library.persistence.item.ClientOAuthSessionItem;
import uk.gov.di.ipv.core.library.persistence.item.IpvSessionItem;
import uk.gov.di.ipv.core.library.service.ClientOAuthSessionDetailsService;
import uk.gov.di.ipv.core.library.service.ConfigService;
import uk.gov.di.ipv.core.library.service.IpvSessionService;
import uk.gov.di.ipv.core.library.service.UserIdentityService;
import uk.gov.di.ipv.core.library.verifiablecredential.helpers.VcHelper;
import uk.gov.di.ipv.core.library.verifiablecredential.service.SessionCredentialsService;

import java.text.ParseException;
import java.util.Comparator;
import java.util.List;
import java.util.Optional;

import static uk.gov.di.ipv.core.library.domain.Cri.ADDRESS;
import static uk.gov.di.ipv.core.library.domain.VerifiableCredentialConstants.VC_CLAIM;
import static uk.gov.di.ipv.core.library.domain.VerifiableCredentialConstants.VC_CREDENTIAL_SUBJECT;

public class BuildProvenUserIdentityDetailsHandler
        implements RequestHandler<APIGatewayProxyRequestEvent, APIGatewayProxyResponseEvent> {
    private static final Logger LOGGER = LogManager.getLogger();
    private final IpvSessionService ipvSessionService;
    private final UserIdentityService userIdentityService;
    private final ConfigService configService;
    private final ClientOAuthSessionDetailsService clientOAuthSessionDetailsService;
    private final SessionCredentialsService sessionCredentialsService;

    private final ObjectMapper mapper = new ObjectMapper();

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
        this.configService = new ConfigService();
        this.ipvSessionService = new IpvSessionService(configService);
        this.userIdentityService = new UserIdentityService(configService);
        this.clientOAuthSessionDetailsService = new ClientOAuthSessionDetailsService(configService);
        this.sessionCredentialsService = new SessionCredentialsService(configService);
        VcHelper.setConfigService(this.configService);
    }

    @Override
    @Tracing
    @Logging(clearState = true)
    public APIGatewayProxyResponseEvent handleRequest(
            APIGatewayProxyRequestEvent input, Context context) {
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

            if (ipvSessionItem.getVot().getProfileType().equals(ProfileType.GPG45)) {
                var addresses = getProvenIdentityAddresses(vcs);
                provenUserIdentityDetailsBuilder.addresses(addresses);
            }

            LOGGER.info(
                    LogHelper.buildLogMessage("Successfully retrieved proven identity response."));

            return ApiGatewayResponseGenerator.proxyJsonResponse(
                    HTTPResponse.SC_OK, provenUserIdentityDetailsBuilder.build());
        } catch (HttpResponseExceptionWithErrorBody | VerifiableCredentialException e) {
            return buildJourneyErrorResponse(e.getErrorResponse(), e.getResponseCode());
        } catch (ParseException | JsonProcessingException | CredentialParseException e) {
            return buildJourneyErrorResponse(ErrorResponse.FAILED_TO_PARSE_ISSUED_CREDENTIALS);
        } catch (ProvenUserIdentityDetailsException e) {
            return buildJourneyErrorResponse(
                    ErrorResponse.FAILED_TO_GENERATE_PROVEN_USER_IDENTITY_DETAILS);
        }
    }

    private APIGatewayProxyResponseEvent buildJourneyErrorResponse(ErrorResponse errorResponse) {
        return buildJourneyErrorResponse(errorResponse, HttpStatus.SC_INTERNAL_SERVER_ERROR);
    }

    private APIGatewayProxyResponseEvent buildJourneyErrorResponse(
            ErrorResponse errorResponse, int statusCode) {
        LOGGER.error(LogHelper.buildLogMessage(errorResponse.getMessage()));
        return ApiGatewayResponseGenerator.proxyJsonResponse(statusCode, errorResponse);
    }

    @Tracing
    private IdentityClaim getProvenIdentity(List<VerifiableCredential> vcs)
            throws ProvenUserIdentityDetailsException, CredentialParseException {
        try {
            final Optional<IdentityClaim> identityClaim =
                    userIdentityService.findIdentityClaim(vcs);

            if (identityClaim.isEmpty()) {
                LOGGER.error(LogHelper.buildLogMessage("Failed to generate identity claim"));
                throw new HttpResponseExceptionWithErrorBody(
                        500, ErrorResponse.FAILED_TO_GENERATE_IDENTIY_CLAIM);
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

    // TODO
    @Tracing
    private List<Address> getProvenIdentityAddresses(List<VerifiableCredential> vcs)
            throws ParseException, JsonProcessingException, ProvenUserIdentityDetailsException {
        for (var vc : vcs) {
            if (vc.getCri().equals(ADDRESS) && VcHelper.isSuccessfulVc(vc)) {
                JsonNode addressNode =
                        mapper.readTree(SignedJWT.parse(vc.getVcString()).getPayload().toString())
                                .path(VC_CLAIM)
                                .path(VC_CREDENTIAL_SUBJECT)
                                .path(ADDRESS.getId());

                List<Address> addressList =
                        mapper.convertValue(addressNode, new TypeReference<>() {});

                return addressList.stream()
                        .sorted(
                                Comparator.comparing(
                                        Address::getValidUntil,
                                        Comparator.nullsFirst(Comparator.reverseOrder())))
                        .toList();
            }
        }
        LOGGER.error(LogHelper.buildLogMessage("Failed to find addresses of proven user identity"));
        throw new ProvenUserIdentityDetailsException(
                "Failed to find addresses of proven user identity");
    }
}
