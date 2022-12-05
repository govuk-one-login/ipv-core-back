package uk.gov.di.ipv.core.buildprovenuseridentitydetails;

import com.amazonaws.services.lambda.runtime.Context;
import com.amazonaws.services.lambda.runtime.RequestHandler;
import com.amazonaws.services.lambda.runtime.events.APIGatewayProxyRequestEvent;
import com.amazonaws.services.lambda.runtime.events.APIGatewayProxyResponseEvent;
import com.amazonaws.util.StringUtils;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.nimbusds.jwt.SignedJWT;
import org.apache.http.HttpStatus;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import uk.gov.di.ipv.core.buildprovenuseridentitydetails.domain.NameAndDateOfBirth;
import uk.gov.di.ipv.core.buildprovenuseridentitydetails.domain.ProvenUserIdentityDetails;
import uk.gov.di.ipv.core.buildprovenuseridentitydetails.exceptions.ProvenUserIdentityDetailsException;
import uk.gov.di.ipv.core.library.annotations.ExcludeFromGeneratedCoverageReport;
import uk.gov.di.ipv.core.library.config.ConfigurationVariable;
import uk.gov.di.ipv.core.library.domain.Address;
import uk.gov.di.ipv.core.library.domain.BirthDate;
import uk.gov.di.ipv.core.library.domain.ErrorResponse;
import uk.gov.di.ipv.core.library.domain.Name;
import uk.gov.di.ipv.core.library.dto.CredentialIssuerConfig;
import uk.gov.di.ipv.core.library.dto.VcStatusDto;
import uk.gov.di.ipv.core.library.exceptions.HttpResponseExceptionWithErrorBody;
import uk.gov.di.ipv.core.library.helpers.ApiGatewayResponseGenerator;
import uk.gov.di.ipv.core.library.helpers.LogHelper;
import uk.gov.di.ipv.core.library.helpers.RequestHelper;
import uk.gov.di.ipv.core.library.helpers.VcHelper;
import uk.gov.di.ipv.core.library.persistence.item.IpvSessionItem;
import uk.gov.di.ipv.core.library.persistence.item.VcStoreItem;
import uk.gov.di.ipv.core.library.service.ConfigurationService;
import uk.gov.di.ipv.core.library.service.IpvSessionService;
import uk.gov.di.ipv.core.library.service.UserIdentityService;

import java.text.ParseException;
import java.util.ArrayList;
import java.util.List;
import java.util.Optional;

import static uk.gov.di.ipv.core.library.domain.VerifiableCredentialConstants.VC_CLAIM;
import static uk.gov.di.ipv.core.library.domain.VerifiableCredentialConstants.VC_CREDENTIAL_SUBJECT;
import static uk.gov.di.ipv.core.library.service.UserIdentityService.ADDRESS_CRI_TYPES;
import static uk.gov.di.ipv.core.library.service.UserIdentityService.ADDRESS_PROPERTY_NAME;
import static uk.gov.di.ipv.core.library.service.UserIdentityService.BIRTH_DATE_PROPERTY_NAME;
import static uk.gov.di.ipv.core.library.service.UserIdentityService.EVIDENCE_CRI_TYPES;
import static uk.gov.di.ipv.core.library.service.UserIdentityService.NAME_PROPERTY_NAME;

public class BuildProvenUserIdentityDetailsHandler
        implements RequestHandler<APIGatewayProxyRequestEvent, APIGatewayProxyResponseEvent> {
    private static final Logger LOGGER = LogManager.getLogger();

    private IpvSessionService ipvSessionService;
    private UserIdentityService userIdentityService;
    private ConfigurationService configurationService;

    private final ObjectMapper mapper = new ObjectMapper();

    public BuildProvenUserIdentityDetailsHandler(
            IpvSessionService ipvSessionService,
            UserIdentityService userIdentityService,
            ConfigurationService configurationService) {
        this.ipvSessionService = ipvSessionService;
        this.userIdentityService = userIdentityService;
        this.configurationService = configurationService;
    }

    @ExcludeFromGeneratedCoverageReport
    public BuildProvenUserIdentityDetailsHandler() {
        this.configurationService = new ConfigurationService();
        this.ipvSessionService = new IpvSessionService(configurationService);
        this.userIdentityService = new UserIdentityService(configurationService);
    }

    @Override
    public APIGatewayProxyResponseEvent handleRequest(
            APIGatewayProxyRequestEvent input, Context context) {
        LogHelper.attachComponentIdToLogs();
        ProvenUserIdentityDetails.Builder provenUserIdentityDetailsBuilder =
                new ProvenUserIdentityDetails.Builder();
        try {
            String ipvSessionId = RequestHelper.getIpvSessionId(input.getHeaders());
            IpvSessionItem ipvSessionItem = ipvSessionService.getIpvSession(ipvSessionId);

            String govukSigninJourneyId =
                    ipvSessionItem.getClientSessionDetails().getGovukSigninJourneyId();
            LogHelper.attachGovukSigninJourneyIdToLogs(govukSigninJourneyId);

            List<VcStoreItem> credentials =
                    userIdentityService.getVcStoreItems(
                            ipvSessionItem.getClientSessionDetails().getUserId());

            List<VcStatusDto> currentVcStatuses = generateCurrentVcStatuses(credentials);

            NameAndDateOfBirth nameAndDateOfBirth =
                    getProvenIdentityNameAndDateOfBirth(credentials, currentVcStatuses);
            provenUserIdentityDetailsBuilder.setName(nameAndDateOfBirth.getName());
            provenUserIdentityDetailsBuilder.setDateOfBirth(nameAndDateOfBirth.getDateOfBirth());

            provenUserIdentityDetailsBuilder.setAddressDetails(
                    getProvenIdentityAddress(credentials, currentVcStatuses));

            LOGGER.info("Successfully retrived proven identity response");

            return ApiGatewayResponseGenerator.proxyJsonResponse(
                    HttpStatus.SC_OK, provenUserIdentityDetailsBuilder.build());
        } catch (HttpResponseExceptionWithErrorBody e) {
            return ApiGatewayResponseGenerator.proxyJsonResponse(
                    e.getResponseCode(), e.getErrorBody());
        } catch (ParseException | JsonProcessingException e) {
            LOGGER.error("Failed to parse credentials");
            return ApiGatewayResponseGenerator.proxyJsonResponse(
                    HttpStatus.SC_INTERNAL_SERVER_ERROR,
                    ErrorResponse.FAILED_TO_PARSE_ISSUED_CREDENTIALS);
        } catch (ProvenUserIdentityDetailsException e) {
            LOGGER.error("Failed generate the proven user identity details");
            return ApiGatewayResponseGenerator.proxyJsonResponse(
                    HttpStatus.SC_INTERNAL_SERVER_ERROR,
                    ErrorResponse.FAILED_TO_GENERATE_PROVEN_USER_IDENTITY_DETAILS);
        }
    }

    private NameAndDateOfBirth getProvenIdentityNameAndDateOfBirth(
            List<VcStoreItem> credentialIssuerItems, List<VcStatusDto> currentVcStatuses)
            throws ParseException, JsonProcessingException, ProvenUserIdentityDetailsException {
        for (VcStoreItem item : credentialIssuerItems) {
            CredentialIssuerConfig credentialIssuerConfig =
                    configurationService.getCredentialIssuer(item.getCredentialIssuer());
            if (EVIDENCE_CRI_TYPES.contains(item.getCredentialIssuer())
                    && userIdentityService.isVcSuccessful(
                            currentVcStatuses, credentialIssuerConfig.getAudienceForClients())) {
                JsonNode vcSubjectNode =
                        mapper.readTree(
                                        SignedJWT.parse(item.getCredential())
                                                .getPayload()
                                                .toString())
                                .path(VC_CLAIM)
                                .path(VC_CREDENTIAL_SUBJECT);

                JsonNode nameNode = vcSubjectNode.path(NAME_PROPERTY_NAME);

                Name name = mapper.convertValue(nameNode.get(0), Name.class);

                StringBuilder nameBuilder = new StringBuilder();
                name.getNameParts()
                        .forEach(
                                namePart -> {
                                    if (nameBuilder.length() == 0) {
                                        nameBuilder.append(namePart.getValue());
                                    } else {
                                        nameBuilder.append(" ").append(namePart.getValue());
                                    }
                                });

                JsonNode dateOfBirthNode = vcSubjectNode.path(BIRTH_DATE_PROPERTY_NAME);

                BirthDate birthDate = mapper.convertValue(dateOfBirthNode.get(0), BirthDate.class);

                return new NameAndDateOfBirth(nameBuilder.toString(), birthDate.getValue());
            }
        }
        LOGGER.error("Failed to find name and date of birth of proven user identity");
        throw new ProvenUserIdentityDetailsException(
                "Failed to find name and date of birth of proven user identity");
    }

    private Address getProvenIdentityAddress(
            List<VcStoreItem> credentialIssuerItems, List<VcStatusDto> currentVcStatuses)
            throws ParseException, JsonProcessingException, ProvenUserIdentityDetailsException {
        for (VcStoreItem item : credentialIssuerItems) {
            CredentialIssuerConfig credentialIssuerConfig =
                    configurationService.getCredentialIssuer(item.getCredentialIssuer());
            if (ADDRESS_CRI_TYPES.contains(item.getCredentialIssuer())
                    && userIdentityService.isVcSuccessful(
                            currentVcStatuses, credentialIssuerConfig.getAudienceForClients())) {
                JsonNode addressNode =
                        mapper.readTree(
                                        SignedJWT.parse(item.getCredential())
                                                .getPayload()
                                                .toString())
                                .path(VC_CLAIM)
                                .path(VC_CREDENTIAL_SUBJECT)
                                .path(ADDRESS_PROPERTY_NAME);

                List<Address> addressList =
                        mapper.convertValue(addressNode, new TypeReference<>() {});

                if (addressList.size() > 1) {
                    Optional<Address> currentAddress =
                            addressList.stream()
                                    .filter(
                                            address ->
                                                    StringUtils.isNullOrEmpty(
                                                            address.getValidUntil()))
                                    .findFirst();

                    return currentAddress.orElseGet(() -> addressList.get(0));
                } else {
                    return addressList.get(0);
                }
            }
        }
        LOGGER.error("Failed to find current address of proven user identity");
        throw new ProvenUserIdentityDetailsException(
                "Failed to find current address of proven user identity");
    }

    private List<VcStatusDto> generateCurrentVcStatuses(List<VcStoreItem> credentials)
            throws ParseException {
        List<VcStatusDto> vcStatuses = new ArrayList<>();

        for (VcStoreItem item : credentials) {
            SignedJWT signedJWT = SignedJWT.parse(item.getCredential());
            String addressCriId =
                    configurationService.getSsmParameter(ConfigurationVariable.ADDRESS_CRI_ID);
            CredentialIssuerConfig addressCriConfig =
                    configurationService.getCredentialIssuer(addressCriId);
            boolean isSuccessful = VcHelper.isSuccessfulVcIgnoringCi(signedJWT, addressCriConfig);

            vcStatuses.add(new VcStatusDto(signedJWT.getJWTClaimsSet().getIssuer(), isSuccessful));
        }
        return vcStatuses;
    }
}
