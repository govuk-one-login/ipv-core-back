package uk.gov.di.ipv.core.selectcri;

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
import software.amazon.lambda.powertools.logging.Logging;
import software.amazon.lambda.powertools.tracing.Tracing;
import uk.gov.di.ipv.core.library.annotations.ExcludeFromGeneratedCoverageReport;
import uk.gov.di.ipv.core.library.domain.ErrorResponse;
import uk.gov.di.ipv.core.library.domain.JourneyResponse;
import uk.gov.di.ipv.core.library.domain.gpg45.Gpg45Profile;
import uk.gov.di.ipv.core.library.domain.gpg45.domain.CredentialEvidenceItem;
import uk.gov.di.ipv.core.library.domain.gpg45.validation.DcmawEvidenceValidator;
import uk.gov.di.ipv.core.library.domain.gpg45.validation.FraudEvidenceValidator;
import uk.gov.di.ipv.core.library.domain.gpg45.validation.KbvEvidenceValidator;
import uk.gov.di.ipv.core.library.domain.gpg45.validation.PassportEvidenceValidator;
import uk.gov.di.ipv.core.library.dto.ClientSessionDetailsDto;
import uk.gov.di.ipv.core.library.dto.VisitedCredentialIssuerDetailsDto;
import uk.gov.di.ipv.core.library.exceptions.HttpResponseExceptionWithErrorBody;
import uk.gov.di.ipv.core.library.helpers.ApiGatewayResponseGenerator;
import uk.gov.di.ipv.core.library.helpers.LogHelper;
import uk.gov.di.ipv.core.library.helpers.RequestHelper;
import uk.gov.di.ipv.core.library.persistence.item.IpvSessionItem;
import uk.gov.di.ipv.core.library.persistence.item.UserIssuedCredentialsItem;
import uk.gov.di.ipv.core.library.service.ConfigurationService;
import uk.gov.di.ipv.core.library.service.IpvSessionService;
import uk.gov.di.ipv.core.library.service.UserIdentityService;

import java.text.ParseException;
import java.util.Arrays;
import java.util.List;
import java.util.Optional;
import java.util.function.BiPredicate;

import static uk.gov.di.ipv.core.library.config.ConfigurationVariable.ADDRESS_CRI_ID;
import static uk.gov.di.ipv.core.library.config.ConfigurationVariable.DCMAW_ALLOWED_USER_IDS;
import static uk.gov.di.ipv.core.library.config.ConfigurationVariable.DCMAW_CRI_ID;
import static uk.gov.di.ipv.core.library.config.ConfigurationVariable.DCMAW_ENABLED;
import static uk.gov.di.ipv.core.library.config.ConfigurationVariable.DCMAW_SHOULD_SEND_ALL_USERS;
import static uk.gov.di.ipv.core.library.config.ConfigurationVariable.FRAUD_CRI_ID;
import static uk.gov.di.ipv.core.library.config.ConfigurationVariable.KBV_CRI_ID;
import static uk.gov.di.ipv.core.library.config.ConfigurationVariable.PASSPORT_CRI_ID;
import static uk.gov.di.ipv.core.library.domain.VerifiableCredentialConstants.VC_CLAIM;
import static uk.gov.di.ipv.core.library.domain.VerifiableCredentialConstants.VC_EVIDENCE;

public class SelectCriHandler
        implements RequestHandler<APIGatewayProxyRequestEvent, APIGatewayProxyResponseEvent> {
    private static final Logger LOGGER = LogManager.getLogger();
    private static final Gson gson = new Gson();
    private static final String CRI_START_JOURNEY = "/journey/%s";
    public static final String JOURNEY_FAIL = "/journey/fail";

    private final ConfigurationService configurationService;
    private final UserIdentityService userIdentityService;
    private final IpvSessionService ipvSessionService;
    private final String passportCriId;
    private final String fraudCriId;
    private final String kbvCriId;
    private final String addressCriId;
    private final String dcmawCriId;

    public SelectCriHandler(
            ConfigurationService configurationService,
            UserIdentityService userIdentityService,
            IpvSessionService ipvSessionService) {
        this.configurationService = configurationService;
        this.userIdentityService = userIdentityService;
        this.ipvSessionService = ipvSessionService;

        passportCriId = configurationService.getSsmParameter(PASSPORT_CRI_ID);
        fraudCriId = configurationService.getSsmParameter(FRAUD_CRI_ID);
        kbvCriId = configurationService.getSsmParameter(KBV_CRI_ID);
        addressCriId = configurationService.getSsmParameter(ADDRESS_CRI_ID);
        dcmawCriId = configurationService.getSsmParameter(DCMAW_CRI_ID);
    }

    @ExcludeFromGeneratedCoverageReport
    public SelectCriHandler() {
        this.configurationService = new ConfigurationService();
        this.userIdentityService = new UserIdentityService(configurationService);
        this.ipvSessionService = new IpvSessionService(configurationService);

        passportCriId = configurationService.getSsmParameter(PASSPORT_CRI_ID);
        fraudCriId = configurationService.getSsmParameter(FRAUD_CRI_ID);
        kbvCriId = configurationService.getSsmParameter(KBV_CRI_ID);
        addressCriId = configurationService.getSsmParameter(ADDRESS_CRI_ID);
        dcmawCriId = configurationService.getSsmParameter(DCMAW_CRI_ID);
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

            logGovUkSignInJourneyId(ipvSessionId);

            List<VisitedCredentialIssuerDetailsDto> visitedCredentialIssuers =
                    ipvSessionItem.getVisitedCredentialIssuerDetails();

            String userId = ipvSessionItem.getClientSessionDetails().getUserId();

            if (shouldSendUserToApp(userId)) {
                return getNextAppJourneyCri(visitedCredentialIssuers, userId);
            } else {
                return getNextWebJourneyCri(visitedCredentialIssuers, userId);
            }
        } catch (HttpResponseExceptionWithErrorBody e) {
            return ApiGatewayResponseGenerator.proxyJsonResponse(
                    e.getResponseCode(), e.getErrorBody());
        } catch (ParseException e) {
            LOGGER.error("Unable to parse existing credentials", e);
            return ApiGatewayResponseGenerator.proxyJsonResponse(
                    HttpStatus.SC_INTERNAL_SERVER_ERROR,
                    ErrorResponse.FAILED_TO_PARSE_ISSUED_CREDENTIALS);
        }
    }

    private APIGatewayProxyResponseEvent getNextWebJourneyCri(
            List<VisitedCredentialIssuerDetailsDto> visitedCredentialIssuers, String userId)
            throws ParseException {
        Optional<APIGatewayProxyResponseEvent> passportResponse =
                getCriResponse(
                        visitedCredentialIssuers,
                        PassportEvidenceValidator::validate,
                        Gpg45Profile.M1A,
                        passportCriId,
                        userId);
        if (passportResponse.isPresent()) {
            return passportResponse.get();
        }

        if (userHasNotVisited(visitedCredentialIssuers, addressCriId)) {
            return getJourneyResponse(addressCriId);
        } else {
            Optional<VisitedCredentialIssuerDetailsDto> addressVisitDetails =
                    visitedCredentialIssuers.stream()
                            .filter(cri -> cri.getCriId().equals(addressCriId))
                            .findFirst();

            if (addressVisitDetails.isPresent() && !addressVisitDetails.get().isReturnedWithVc()) {
                LOGGER.info(
                        "User has a previous failed visit to address cri due to: {}. Routing user to web journey instead.",
                        addressVisitDetails.get().getOauthError());
                return getJourneyPyiNoMatchResponse();
            }
        }

        Optional<APIGatewayProxyResponseEvent> fraudResponse =
                getCriResponse(
                        visitedCredentialIssuers,
                        FraudEvidenceValidator::validate,
                        Gpg45Profile.M1A,
                        fraudCriId,
                        userId);
        if (fraudResponse.isPresent()) {
            return fraudResponse.get();
        }

        Optional<APIGatewayProxyResponseEvent> kbvResponse =
                getCriResponse(
                        visitedCredentialIssuers,
                        KbvEvidenceValidator::validate,
                        Gpg45Profile.M1A,
                        kbvCriId,
                        userId);
        if (kbvResponse.isPresent()) {
            return kbvResponse.get();
        }

        LOGGER.info("Unable to determine next credential issuer");
        return ApiGatewayResponseGenerator.proxyJsonResponse(
                HttpStatus.SC_OK, new JourneyResponse(JOURNEY_FAIL));
    }

    private APIGatewayProxyResponseEvent getNextAppJourneyCri(
            List<VisitedCredentialIssuerDetailsDto> visitedCredentialIssuers, String userId)
            throws ParseException {
        Optional<APIGatewayProxyResponseEvent> dcmawResponse =
                getCriResponse(
                        visitedCredentialIssuers,
                        DcmawEvidenceValidator::validate,
                        Gpg45Profile.M1B,
                        dcmawCriId,
                        userId);
        if (dcmawResponse.isPresent()) {
            return dcmawResponse.get();
        }

        if (userHasNotVisited(visitedCredentialIssuers, addressCriId)) {
            return getJourneyResponse(addressCriId);
        } else {
            Optional<VisitedCredentialIssuerDetailsDto> addressVisitDetails =
                    visitedCredentialIssuers.stream()
                            .filter(cri -> cri.getCriId().equals(addressCriId))
                            .findFirst();

            if (addressVisitDetails.isPresent() && !addressVisitDetails.get().isReturnedWithVc()) {
                LOGGER.info(
                        "User has a previous failed visit to address cri due to: {}. Routing user to web journey instead.",
                        addressVisitDetails.get().getOauthError());
                return getJourneyPyiNoMatchResponse();
            }
        }

        Optional<APIGatewayProxyResponseEvent> fraudResponse =
                getCriResponse(
                        visitedCredentialIssuers,
                        FraudEvidenceValidator::validate,
                        Gpg45Profile.M1B,
                        fraudCriId,
                        userId);
        if (fraudResponse.isPresent()) {
            return fraudResponse.get();
        }

        LOGGER.info("Unable to determine next credential issuer");
        return ApiGatewayResponseGenerator.proxyJsonResponse(
                HttpStatus.SC_OK, new JourneyResponse(JOURNEY_FAIL));
    }

    private void logGovUkSignInJourneyId(String ipvSessionId) {
        IpvSessionItem ipvSessionItem = ipvSessionService.getIpvSession(ipvSessionId);
        ClientSessionDetailsDto clientSessionDetailsDto = ipvSessionItem.getClientSessionDetails();
        LogHelper.attachGovukSigninJourneyIdToLogs(
                clientSessionDetailsDto.getGovukSigninJourneyId());
    }

    private APIGatewayProxyResponseEvent getJourneyResponse(String criId) {
        return ApiGatewayResponseGenerator.proxyJsonResponse(
                HttpStatus.SC_OK, new JourneyResponse(String.format(CRI_START_JOURNEY, criId)));
    }

    private APIGatewayProxyResponseEvent getJourneyPyiNoMatchResponse() {
        return ApiGatewayResponseGenerator.proxyJsonResponse(
                HttpStatus.SC_OK, new JourneyResponse("/journey/pyi-no-match"));
    }

    private boolean userHasNotVisited(
            List<VisitedCredentialIssuerDetailsDto> visitedCredentialIssuers, String criId) {
        return visitedCredentialIssuers.stream().noneMatch(cri -> cri.getCriId().equals(criId));
    }

    private Optional<APIGatewayProxyResponseEvent> getCriResponse(
            List<VisitedCredentialIssuerDetailsDto> visitedCredentialIssuers,
            BiPredicate<CredentialEvidenceItem, Gpg45Profile> gpg45Validator,
            Gpg45Profile gpg45Profile,
            String criId,
            String userId)
            throws ParseException {
        if (userHasNotVisited(visitedCredentialIssuers, criId)) {
            return Optional.of(getJourneyResponse(criId));
        } else {
            Optional<APIGatewayProxyResponseEvent> failedJourneyResponse =
                    getFailedJourneyResponse(
                            visitedCredentialIssuers, gpg45Validator, gpg45Profile, criId, userId);

            if (failedJourneyResponse.isPresent()) {
                if (criId.equals(dcmawCriId)) {
                    LOGGER.info("Routing user to web journey");
                    return Optional.of(getNextWebJourneyCri(visitedCredentialIssuers, userId));
                }
                LOGGER.info("Routing user to failed journey path");
            }
            return failedJourneyResponse;
        }
    }

    private Optional<APIGatewayProxyResponseEvent> getFailedJourneyResponse(
            List<VisitedCredentialIssuerDetailsDto> visitedCredentialIssuers,
            BiPredicate<CredentialEvidenceItem, Gpg45Profile> validator,
            Gpg45Profile gpg45Profile,
            String criId,
            String userId)
            throws ParseException {
        Optional<VisitedCredentialIssuerDetailsDto> criVisitDetails =
                visitedCredentialIssuers.stream()
                        .filter(cri -> cri.getCriId().equals(criId))
                        .findFirst();

        if (criVisitDetails.isPresent()) {
            if (criVisitDetails.get().isReturnedWithVc()) {
                if (!isSuccessfulVc(userId, criId, validator, gpg45Profile)) {
                    LOGGER.info(
                            "User has a previous failed visit to {} cri due to a failed identity check",
                            criId);
                    return Optional.of(getJourneyPyiNoMatchResponse());
                }
            } else {
                LOGGER.info(
                        "User has a previous failed visit to {} cri due to: {}",
                        criId,
                        criVisitDetails.get().getOauthError());
                return Optional.of(getJourneyPyiNoMatchResponse());
            }
        }
        return Optional.empty();
    }

    private boolean isSuccessfulVc(
            String userId,
            String criId,
            BiPredicate<CredentialEvidenceItem, Gpg45Profile> validator,
            Gpg45Profile gpg45Profile)
            throws ParseException {
        UserIssuedCredentialsItem userIssuedCredentialsItem =
                userIdentityService.getUserIssuedCredential(userId, criId);

        JSONObject vcClaim =
                (JSONObject)
                        SignedJWT.parse(userIssuedCredentialsItem.getCredential())
                                .getJWTClaimsSet()
                                .getClaim(VC_CLAIM);
        JSONArray evidenceArray = (JSONArray) vcClaim.get(VC_EVIDENCE);

        List<CredentialEvidenceItem> credentialEvidenceList =
                gson.fromJson(
                        evidenceArray.toJSONString(),
                        new TypeToken<List<CredentialEvidenceItem>>() {}.getType());

        for (CredentialEvidenceItem item : credentialEvidenceList) {
            if (!validator.test(item, gpg45Profile)) {
                return false;
            }
        }
        return true;
    }

    private boolean shouldSendUserToApp(String userId) {
        boolean dcmawEnabled =
                Boolean.parseBoolean(configurationService.getSsmParameter(DCMAW_ENABLED));
        if (dcmawEnabled) {
            boolean shouldSendAllUsers =
                    Boolean.parseBoolean(
                            configurationService.getSsmParameter(DCMAW_SHOULD_SEND_ALL_USERS));

            if (!shouldSendAllUsers) {
                String userIds = configurationService.getSsmParameter(DCMAW_ALLOWED_USER_IDS);
                List<String> dcmawAllowedUserIds = Arrays.asList(userIds.split(","));
                return dcmawAllowedUserIds.contains(userId);
            }
            return true;
        } else {
            return false;
        }
    }
}
