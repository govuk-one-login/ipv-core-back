package uk.gov.di.ipv.core.buildprovenuseridentitydetails;

import com.amazonaws.services.lambda.runtime.Context;
import com.amazonaws.services.lambda.runtime.RequestHandler;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.nimbusds.jwt.SignedJWT;
import org.apache.http.HttpStatus;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import software.amazon.lambda.powertools.logging.Logging;
import software.amazon.lambda.powertools.tracing.Tracing;
import uk.gov.di.ipv.core.buildprovenuseridentitydetails.domain.NameAndDateOfBirth;
import uk.gov.di.ipv.core.buildprovenuseridentitydetails.domain.ProvenUserIdentityDetails;
import uk.gov.di.ipv.core.buildprovenuseridentitydetails.exceptions.ProvenUserIdentityDetailsException;
import uk.gov.di.ipv.core.library.annotations.ExcludeFromGeneratedCoverageReport;
import uk.gov.di.ipv.core.library.domain.Address;
import uk.gov.di.ipv.core.library.domain.BirthDate;
import uk.gov.di.ipv.core.library.domain.ErrorResponse;
import uk.gov.di.ipv.core.library.domain.IdentityClaim;
import uk.gov.di.ipv.core.library.domain.JourneyErrorResponse;
import uk.gov.di.ipv.core.library.domain.JourneyRequest;
import uk.gov.di.ipv.core.library.domain.Name;
import uk.gov.di.ipv.core.library.dto.VcStatusDto;
import uk.gov.di.ipv.core.library.exceptions.CredentialParseException;
import uk.gov.di.ipv.core.library.exceptions.HttpResponseExceptionWithErrorBody;
import uk.gov.di.ipv.core.library.exceptions.NoVcStatusForIssuerException;
import uk.gov.di.ipv.core.library.helpers.LogHelper;
import uk.gov.di.ipv.core.library.helpers.RequestHelper;
import uk.gov.di.ipv.core.library.persistence.item.ClientOAuthSessionItem;
import uk.gov.di.ipv.core.library.persistence.item.IpvSessionItem;
import uk.gov.di.ipv.core.library.persistence.item.VcStoreItem;
import uk.gov.di.ipv.core.library.service.ClientOAuthSessionDetailsService;
import uk.gov.di.ipv.core.library.service.ConfigService;
import uk.gov.di.ipv.core.library.service.IpvSessionService;
import uk.gov.di.ipv.core.library.service.UserIdentityService;
import uk.gov.di.ipv.core.library.verifiablecredential.helpers.VcHelper;
import uk.gov.di.ipv.core.library.verifiablecredential.service.VerifiableCredentialService;

import java.text.ParseException;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.List;
import java.util.Map;
import java.util.Optional;

import static uk.gov.di.ipv.core.library.domain.CriConstants.ADDRESS_CRI;
import static uk.gov.di.ipv.core.library.domain.VerifiableCredentialConstants.VC_CLAIM;
import static uk.gov.di.ipv.core.library.domain.VerifiableCredentialConstants.VC_CREDENTIAL_SUBJECT;
import static uk.gov.di.ipv.core.library.journeyuris.JourneyUris.JOURNEY_ERROR_PATH;

public class BuildProvenUserIdentityDetailsHandler
        implements RequestHandler<JourneyRequest, Map<String, Object>> {
    private static final Logger LOGGER = LogManager.getLogger();

    private final IpvSessionService ipvSessionService;
    private final UserIdentityService userIdentityService;
    private final ConfigService configService;
    private final ClientOAuthSessionDetailsService clientOAuthSessionDetailsService;
    private final VerifiableCredentialService verifiableCredentialService;

    private final ObjectMapper mapper = new ObjectMapper();

    public BuildProvenUserIdentityDetailsHandler(
            IpvSessionService ipvSessionService,
            UserIdentityService userIdentityService,
            ConfigService configService,
            ClientOAuthSessionDetailsService clientOAuthSessionDetailsService,
            VerifiableCredentialService verifiableCredentialService) {
        this.ipvSessionService = ipvSessionService;
        this.userIdentityService = userIdentityService;
        this.configService = configService;
        this.clientOAuthSessionDetailsService = clientOAuthSessionDetailsService;
        this.verifiableCredentialService = verifiableCredentialService;
        VcHelper.setConfigService(this.configService);
    }

    @ExcludeFromGeneratedCoverageReport
    public BuildProvenUserIdentityDetailsHandler() {
        this.configService = new ConfigService();
        this.ipvSessionService = new IpvSessionService(configService);
        this.userIdentityService = new UserIdentityService(configService);
        this.clientOAuthSessionDetailsService = new ClientOAuthSessionDetailsService(configService);
        this.verifiableCredentialService = new VerifiableCredentialService(configService);
        VcHelper.setConfigService(this.configService);
    }

    @Override
    @Tracing
    @Logging(clearState = true)
    public Map<String, Object> handleRequest(JourneyRequest input, Context context) {
        LogHelper.attachComponentIdToLogs(configService);
        ProvenUserIdentityDetails.ProvenUserIdentityDetailsBuilder
                provenUserIdentityDetailsBuilder = ProvenUserIdentityDetails.builder();
        try {
            String featureSet = RequestHelper.getFeatureSet(input);
            configService.setFeatureSet(featureSet);
            String ipvSessionId = RequestHelper.getIpvSessionId(input);
            IpvSessionItem ipvSessionItem = ipvSessionService.getIpvSession(ipvSessionId);

            ClientOAuthSessionItem clientOAuthSessionItem =
                    clientOAuthSessionDetailsService.getClientOAuthSession(
                            ipvSessionItem.getClientOAuthSessionId());

            String govukSigninJourneyId = clientOAuthSessionItem.getGovukSigninJourneyId();
            LogHelper.attachGovukSigninJourneyIdToLogs(govukSigninJourneyId);

            List<VcStoreItem> credentials =
                    verifiableCredentialService.getVcStoreItems(clientOAuthSessionItem.getUserId());

            List<VcStatusDto> currentVcStatuses = generateCurrentVcStatuses(credentials);

            NameAndDateOfBirth nameAndDateOfBirth =
                    getProvenIdentityNameAndDateOfBirth(credentials);
            provenUserIdentityDetailsBuilder.name(nameAndDateOfBirth.getName());
            provenUserIdentityDetailsBuilder.dateOfBirth(nameAndDateOfBirth.getDateOfBirth());

            List<Address> addresses = getProvenIdentityAddresses(credentials, currentVcStatuses);
            provenUserIdentityDetailsBuilder.addresses(addresses);

            LOGGER.info("Successfully retrieved proven identity response.");

            return provenUserIdentityDetailsBuilder.build().toObjectMap();
        } catch (HttpResponseExceptionWithErrorBody e) {
            return new JourneyErrorResponse(
                            JOURNEY_ERROR_PATH, e.getResponseCode(), e.getErrorResponse())
                    .toObjectMap();
        } catch (ParseException | JsonProcessingException | CredentialParseException e) {
            LOGGER.error("Failed to parse credentials");
            return new JourneyErrorResponse(
                            JOURNEY_ERROR_PATH,
                            HttpStatus.SC_INTERNAL_SERVER_ERROR,
                            ErrorResponse.FAILED_TO_PARSE_ISSUED_CREDENTIALS)
                    .toObjectMap();
        } catch (ProvenUserIdentityDetailsException e) {
            LOGGER.error("Failed generate the proven user identity details");
            return new JourneyErrorResponse(
                            JOURNEY_ERROR_PATH,
                            HttpStatus.SC_INTERNAL_SERVER_ERROR,
                            ErrorResponse.FAILED_TO_GENERATE_PROVEN_USER_IDENTITY_DETAILS)
                    .toObjectMap();
        } catch (NoVcStatusForIssuerException e) {
            LOGGER.error("No VC status found for issuer", e);
            return new JourneyErrorResponse(
                            JOURNEY_ERROR_PATH,
                            HttpStatus.SC_INTERNAL_SERVER_ERROR,
                            ErrorResponse.NO_VC_STATUS_FOR_CREDENTIAL_ISSUER)
                    .toObjectMap();
        }
    }

    @Tracing
    private NameAndDateOfBirth getProvenIdentityNameAndDateOfBirth(
            List<VcStoreItem> credentialIssuerItems)
            throws ProvenUserIdentityDetailsException, CredentialParseException {
        try {
            final Optional<IdentityClaim> identityClaim =
                    userIdentityService.findIdentityClaim(credentialIssuerItems);

            if (identityClaim.isEmpty()) {
                LOGGER.error("Failed to generate identity claim");
                throw new HttpResponseExceptionWithErrorBody(
                        500, ErrorResponse.FAILED_TO_GENERATE_IDENTIY_CLAIM);
            }

            BirthDate birthDate =
                    mapper.convertValue(identityClaim.get().getBirthDate().get(0), BirthDate.class);

            return new NameAndDateOfBirth(identityClaim.get().getFullName(), birthDate.getValue());
        } catch (HttpResponseExceptionWithErrorBody e) {
            LOGGER.error("Failed to find name and date of birth of proven user identity");
            throw new ProvenUserIdentityDetailsException(
                    "Failed to find name and date of birth of proven user identity");
        }
    }

    @Tracing
    private List<Address> getProvenIdentityAddresses(
            List<VcStoreItem> credentialIssuerItems, List<VcStatusDto> currentVcStatuses)
            throws ParseException, JsonProcessingException, ProvenUserIdentityDetailsException,
                    NoVcStatusForIssuerException {
        for (VcStoreItem item : credentialIssuerItems) {
            if (item.getCredentialIssuer().equals(ADDRESS_CRI)
                    && userIdentityService.isVcSuccessful(
                            currentVcStatuses,
                            configService.getComponentId(item.getCredentialIssuer()))) {
                JsonNode addressNode =
                        mapper.readTree(
                                        SignedJWT.parse(item.getCredential())
                                                .getPayload()
                                                .toString())
                                .path(VC_CLAIM)
                                .path(VC_CREDENTIAL_SUBJECT)
                                .path(ADDRESS_CRI);

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
        LOGGER.error("Failed to find addresses of proven user identity");
        throw new ProvenUserIdentityDetailsException(
                "Failed to find addresses of proven user identity");
    }

    @Tracing
    private List<VcStatusDto> generateCurrentVcStatuses(List<VcStoreItem> credentials)
            throws ParseException {
        List<VcStatusDto> vcStatuses = new ArrayList<>();

        for (VcStoreItem item : credentials) {
            SignedJWT signedJWT = SignedJWT.parse(item.getCredential());
            boolean isSuccessful = VcHelper.isSuccessfulVc(signedJWT);

            vcStatuses.add(new VcStatusDto(signedJWT.getJWTClaimsSet().getIssuer(), isSuccessful));
        }
        return vcStatuses;
    }
}
