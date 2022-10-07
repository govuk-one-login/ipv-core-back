package uk.gov.di.ipv.core.evaluategpg45scores;

import com.amazonaws.services.lambda.runtime.Context;
import com.amazonaws.services.lambda.runtime.RequestHandler;
import com.amazonaws.services.lambda.runtime.events.APIGatewayProxyRequestEvent;
import com.amazonaws.services.lambda.runtime.events.APIGatewayProxyResponseEvent;
import com.google.gson.Gson;
import com.google.gson.reflect.TypeToken;
import com.nimbusds.jose.shaded.json.JSONArray;
import com.nimbusds.jose.shaded.json.JSONObject;
import com.nimbusds.jwt.SignedJWT;
import org.apache.http.HttpStatus;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.apache.logging.log4j.message.MapMessage;
import software.amazon.lambda.powertools.logging.Logging;
import software.amazon.lambda.powertools.tracing.Tracing;
import uk.gov.di.ipv.core.library.domain.ErrorResponse;
import uk.gov.di.ipv.core.library.domain.JourneyResponse;
import uk.gov.di.ipv.core.library.domain.gpg45.Gpg45Profile;
import uk.gov.di.ipv.core.library.domain.gpg45.Gpg45ProfileEvaluator;
import uk.gov.di.ipv.core.library.domain.gpg45.domain.CredentialEvidenceItem;
import uk.gov.di.ipv.core.library.domain.gpg45.exception.UnknownEvidenceTypeException;
import uk.gov.di.ipv.core.library.domain.gpg45.validation.Gpg45DcmawValidator;
import uk.gov.di.ipv.core.library.domain.gpg45.validation.Gpg45EvidenceValidator;
import uk.gov.di.ipv.core.library.domain.gpg45.validation.Gpg45FraudValidator;
import uk.gov.di.ipv.core.library.domain.gpg45.validation.Gpg45VerificationValidator;
import uk.gov.di.ipv.core.library.dto.ClientSessionDetailsDto;
import uk.gov.di.ipv.core.library.dto.CredentialIssuerConfig;
import uk.gov.di.ipv.core.library.dto.VcStatusDto;
import uk.gov.di.ipv.core.library.exceptions.CiRetrievalException;
import uk.gov.di.ipv.core.library.exceptions.HttpResponseExceptionWithErrorBody;
import uk.gov.di.ipv.core.library.helpers.ApiGatewayResponseGenerator;
import uk.gov.di.ipv.core.library.helpers.LogHelper;
import uk.gov.di.ipv.core.library.helpers.RequestHelper;
import uk.gov.di.ipv.core.library.persistence.item.IpvSessionItem;
import uk.gov.di.ipv.core.library.service.CiStorageService;
import uk.gov.di.ipv.core.library.service.ConfigurationService;
import uk.gov.di.ipv.core.library.service.IpvSessionService;
import uk.gov.di.ipv.core.library.service.UserIdentityService;

import java.text.ParseException;
import java.util.ArrayList;
import java.util.List;
import java.util.Optional;

import static uk.gov.di.ipv.core.library.config.ConfigurationVariable.ADDRESS_CRI_ID;
import static uk.gov.di.ipv.core.library.domain.VerifiableCredentialConstants.VC_CLAIM;
import static uk.gov.di.ipv.core.library.domain.VerifiableCredentialConstants.VC_EVIDENCE;

public class EvaluateGpg45ScoresHandler
        implements RequestHandler<APIGatewayProxyRequestEvent, APIGatewayProxyResponseEvent> {

    public static final List<Gpg45Profile> ACCEPTED_PROFILES =
            List.of(Gpg45Profile.M1A, Gpg45Profile.M1B);
    public static final JourneyResponse JOURNEY_END = new JourneyResponse("/journey/end");
    public static final JourneyResponse JOURNEY_NEXT = new JourneyResponse("/journey/next");
    public static final String VOT_P2 = "P2";
    private static final Logger LOGGER = LogManager.getLogger();
    private static final Gson gson = new Gson();
    private final UserIdentityService userIdentityService;
    private final IpvSessionService ipvSessionService;
    private final Gpg45ProfileEvaluator gpg45ProfileEvaluator;
    private final ConfigurationService configurationService;
    private final String addressCriId;

    public EvaluateGpg45ScoresHandler(
            UserIdentityService userIdentityService,
            IpvSessionService ipvSessionService,
            Gpg45ProfileEvaluator gpg45ProfileEvaluator,
            ConfigurationService configurationService) {
        this.userIdentityService = userIdentityService;
        this.ipvSessionService = ipvSessionService;
        this.gpg45ProfileEvaluator = gpg45ProfileEvaluator;
        this.configurationService = configurationService;

        addressCriId = configurationService.getSsmParameter(ADDRESS_CRI_ID);
    }

    public EvaluateGpg45ScoresHandler() {
        this.configurationService = new ConfigurationService();
        this.userIdentityService = new UserIdentityService(configurationService);
        this.ipvSessionService = new IpvSessionService(configurationService);
        this.gpg45ProfileEvaluator =
                new Gpg45ProfileEvaluator(
                        new CiStorageService(configurationService), configurationService);

        addressCriId = configurationService.getSsmParameter(ADDRESS_CRI_ID);
    }

    @Override
    @Tracing
    @Logging(clearState = true)
    public APIGatewayProxyResponseEvent handleRequest(
            APIGatewayProxyRequestEvent event, Context context) {
        LogHelper.attachComponentIdToLogs();

        try {
            String ipvSessionId = RequestHelper.getIpvSessionId(event);
            IpvSessionItem ipvSessionItem = ipvSessionService.getIpvSession(ipvSessionId);
            ClientSessionDetailsDto clientSessionDetailsDto =
                    ipvSessionItem.getClientSessionDetails();
            String userId = clientSessionDetailsDto.getUserId();

            String govukSigninJourneyId = clientSessionDetailsDto.getGovukSigninJourneyId();
            LogHelper.attachGovukSigninJourneyIdToLogs(govukSigninJourneyId);

            List<String> credentials = userIdentityService.getUserIssuedCredentials(userId);

            Optional<JourneyResponse> contraIndicatorErrorJourneyResponse =
                    gpg45ProfileEvaluator.getJourneyResponseForStoredCis(clientSessionDetailsDto);
            if (contraIndicatorErrorJourneyResponse.isEmpty()) {
                boolean credentialsSatisfyProfile =
                        gpg45ProfileEvaluator.credentialsSatisfyAnyProfile(
                                gpg45ProfileEvaluator.parseGpg45ScoresFromCredentials(credentials),
                                ACCEPTED_PROFILES);
                JourneyResponse journeyResponse;
                var message = new MapMessage();

                if (credentialsSatisfyProfile) {
                    ipvSessionItem.setVot(VOT_P2);
                    journeyResponse = JOURNEY_END;
                    message.with("lambdaResult", "A GPG45 profile has been met")
                            .with("journeyResponse", JOURNEY_END);
                } else {
                    journeyResponse = JOURNEY_NEXT;
                    message.with("lambdaResult", "No GPG45 profiles have been met")
                            .with("journeyResponse", JOURNEY_NEXT);
                }

                updateSuccessfulVcStatuses(ipvSessionItem, credentials);

                LOGGER.info(message);

                return ApiGatewayResponseGenerator.proxyJsonResponse(
                        HttpStatus.SC_OK, journeyResponse);
            } else {
                return ApiGatewayResponseGenerator.proxyJsonResponse(
                        HttpStatus.SC_OK, contraIndicatorErrorJourneyResponse.get());
            }

        } catch (HttpResponseExceptionWithErrorBody e) {
            return ApiGatewayResponseGenerator.proxyJsonResponse(
                    e.getResponseCode(), e.getErrorBody());
        } catch (ParseException e) {
            LOGGER.error("Unable to parse GPG45 scores from existing credentials", e);
            return ApiGatewayResponseGenerator.proxyJsonResponse(
                    HttpStatus.SC_INTERNAL_SERVER_ERROR,
                    ErrorResponse.FAILED_TO_PARSE_ISSUED_CREDENTIALS);
        } catch (UnknownEvidenceTypeException e) {
            LOGGER.error("Unable to determine type of credential", e);
            return ApiGatewayResponseGenerator.proxyJsonResponse(
                    HttpStatus.SC_INTERNAL_SERVER_ERROR,
                    ErrorResponse.FAILED_TO_DETERMINE_CREDENTIAL_TYPE);
        } catch (CiRetrievalException e) {
            LOGGER.error("Error when fetching CIs from storage system", e);
            return ApiGatewayResponseGenerator.proxyJsonResponse(
                    HttpStatus.SC_INTERNAL_SERVER_ERROR, ErrorResponse.FAILED_TO_GET_STORED_CIS);
        }
    }

    @Tracing
    private void updateSuccessfulVcStatuses(IpvSessionItem ipvSessionItem, List<String> credentials)
            throws ParseException {

        // get list of success vc's
        List<VcStatusDto> currentVcStatusDtos = ipvSessionItem.getCurrentVcStatuses();

        if (currentVcStatusDtos == null) {
            currentVcStatusDtos = new ArrayList<>();
        }

        if (currentVcStatusDtos.size() != credentials.size()) {
            List<VcStatusDto> updatedStatuses = generateVcSuccessStatuses(credentials);
            ipvSessionItem.setCurrentVcStatuses(updatedStatuses);
            ipvSessionService.updateIpvSession(ipvSessionItem);
        }
    }

    private List<VcStatusDto> generateVcSuccessStatuses(List<String> credentials)
            throws ParseException {
        List<VcStatusDto> vcStatuses = new ArrayList<>();

        for (String credential : credentials) {
            SignedJWT signedJWT = SignedJWT.parse(credential);
            JSONObject vcClaim = (JSONObject) signedJWT.getJWTClaimsSet().getClaim(VC_CLAIM);
            JSONArray evidenceArray = (JSONArray) vcClaim.get(VC_EVIDENCE);
            if (evidenceArray == null) {
                CredentialIssuerConfig addressCriConfig =
                        configurationService.getCredentialIssuer(addressCriId);
                String vcIss = signedJWT.getJWTClaimsSet().getIssuer();
                if (vcIss.equals(addressCriConfig.getAudienceForClients())) {
                    vcStatuses.add(new VcStatusDto(vcIss, true));
                }
                LOGGER.warn("Unexpected missing evidence on VC from issuer: {}", vcIss);
                continue;
            }

            List<CredentialEvidenceItem> credentialEvidenceList =
                    gson.fromJson(
                            evidenceArray.toJSONString(),
                            new TypeToken<List<CredentialEvidenceItem>>() {}.getType());

            boolean isSuccessful = isSuccessfulVc(credentialEvidenceList);

            vcStatuses.add(new VcStatusDto(signedJWT.getJWTClaimsSet().getIssuer(), isSuccessful));
        }
        return vcStatuses;
    }

    private boolean isSuccessfulVc(List<CredentialEvidenceItem> credentialEvidenceList) {
        try {
            for (CredentialEvidenceItem item : credentialEvidenceList) {
                boolean result = isValidEvidence(item);
                if (result) {
                    return true;
                }
            }
            return false;
        } catch (UnknownEvidenceTypeException e) {
            return false;
        }
    }

    private boolean isValidEvidence(CredentialEvidenceItem item)
            throws UnknownEvidenceTypeException {
        if (item.getType().equals(CredentialEvidenceItem.EvidenceType.EVIDENCE)) {
            return Gpg45EvidenceValidator.isSuccessful(item);
        } else if (item.getType().equals(CredentialEvidenceItem.EvidenceType.IDENTITY_FRAUD)) {
            return Gpg45FraudValidator.isSuccessful(item);
        } else if (item.getType().equals(CredentialEvidenceItem.EvidenceType.VERIFICATION)) {
            return Gpg45VerificationValidator.isSuccessful(item);
        } else if (item.getType().equals(CredentialEvidenceItem.EvidenceType.DCMAW)) {
            return Gpg45DcmawValidator.isSuccessful(item);
        }
        throw new UnknownEvidenceTypeException();
    }
}
