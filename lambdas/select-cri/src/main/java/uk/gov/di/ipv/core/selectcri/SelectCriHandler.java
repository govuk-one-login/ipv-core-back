package uk.gov.di.ipv.core.selectcri;

import com.amazonaws.services.lambda.runtime.Context;
import com.amazonaws.services.lambda.runtime.RequestHandler;
import com.amazonaws.services.lambda.runtime.events.APIGatewayProxyRequestEvent;
import com.amazonaws.services.lambda.runtime.events.APIGatewayProxyResponseEvent;
import org.apache.http.HttpStatus;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.apache.logging.log4j.message.StringMapMessage;
import software.amazon.lambda.powertools.logging.Logging;
import software.amazon.lambda.powertools.tracing.Tracing;
import uk.gov.di.ipv.core.library.annotations.ExcludeFromGeneratedCoverageReport;
import uk.gov.di.ipv.core.library.domain.ErrorResponse;
import uk.gov.di.ipv.core.library.domain.JourneyResponse;
import uk.gov.di.ipv.core.library.dto.ClientSessionDetailsDto;
import uk.gov.di.ipv.core.library.dto.CredentialIssuerConfig;
import uk.gov.di.ipv.core.library.dto.VcStatusDto;
import uk.gov.di.ipv.core.library.dto.VisitedCredentialIssuerDetailsDto;
import uk.gov.di.ipv.core.library.exceptions.HttpResponseExceptionWithErrorBody;
import uk.gov.di.ipv.core.library.helpers.ApiGatewayResponseGenerator;
import uk.gov.di.ipv.core.library.helpers.LogHelper;
import uk.gov.di.ipv.core.library.helpers.RequestHelper;
import uk.gov.di.ipv.core.library.persistence.item.IpvSessionItem;
import uk.gov.di.ipv.core.library.service.ConfigService;
import uk.gov.di.ipv.core.library.service.IpvSessionService;

import java.text.ParseException;
import java.util.Arrays;
import java.util.List;
import java.util.Optional;

import static uk.gov.di.ipv.core.library.config.ConfigurationVariable.ADDRESS_CRI_ID;
import static uk.gov.di.ipv.core.library.config.ConfigurationVariable.DCMAW_ALLOWED_USER_IDS;
import static uk.gov.di.ipv.core.library.config.ConfigurationVariable.DCMAW_CRI_ID;
import static uk.gov.di.ipv.core.library.config.ConfigurationVariable.DCMAW_ENABLED;
import static uk.gov.di.ipv.core.library.config.ConfigurationVariable.DCMAW_SHOULD_SEND_ALL_USERS;
import static uk.gov.di.ipv.core.library.config.ConfigurationVariable.DRIVING_LICENCE_CRI_ID;
import static uk.gov.di.ipv.core.library.config.ConfigurationVariable.FRAUD_CRI_ID;
import static uk.gov.di.ipv.core.library.config.ConfigurationVariable.KBV_CRI_ID;
import static uk.gov.di.ipv.core.library.config.ConfigurationVariable.PASSPORT_CRI_ID;

public class SelectCriHandler
        implements RequestHandler<APIGatewayProxyRequestEvent, APIGatewayProxyResponseEvent> {
    private static final Logger LOGGER = LogManager.getLogger();
    private static final String CRI_START_JOURNEY = "/journey/%s";
    private static final String JOURNEY_FAIL = "/journey/fail";
    private static final String DCMAW_SUCCESS_PAGE = "dcmaw-success";
    private static final String APP_JOURNEY_USER_ID_PREFIX = "urn:uuid:app-journey-user-";
    private static final String UK_PASSPORT_AND_DRIVING_LICENCE_PAGE =
            "ukPassportAndDrivingLicence";
    private static final String STUB_UK_PASSPORT_AND_DRIVING_LICENCE_PAGE =
            "stubUkPassportAndDrivingLicence";

    private final ConfigService configService;
    private final IpvSessionService ipvSessionService;
    private final String passportCriId;
    private final String fraudCriId;
    private final String kbvCriId;
    private final String addressCriId;
    private final String dcmawCriId;
    private final String drivingLicenceCriId;

    public SelectCriHandler(ConfigService configService, IpvSessionService ipvSessionService) {
        this.configService = configService;
        this.ipvSessionService = ipvSessionService;

        passportCriId = configService.getSsmParameter(PASSPORT_CRI_ID);
        fraudCriId = configService.getSsmParameter(FRAUD_CRI_ID);
        kbvCriId = configService.getSsmParameter(KBV_CRI_ID);
        addressCriId = configService.getSsmParameter(ADDRESS_CRI_ID);
        dcmawCriId = configService.getSsmParameter(DCMAW_CRI_ID);
        drivingLicenceCriId = configService.getSsmParameter(DRIVING_LICENCE_CRI_ID);
    }

    @ExcludeFromGeneratedCoverageReport
    public SelectCriHandler() {
        this.configService = new ConfigService();
        this.ipvSessionService = new IpvSessionService(configService);

        passportCriId = configService.getSsmParameter(PASSPORT_CRI_ID);
        fraudCriId = configService.getSsmParameter(FRAUD_CRI_ID);
        kbvCriId = configService.getSsmParameter(KBV_CRI_ID);
        addressCriId = configService.getSsmParameter(ADDRESS_CRI_ID);
        dcmawCriId = configService.getSsmParameter(DCMAW_CRI_ID);
        drivingLicenceCriId = configService.getSsmParameter(DRIVING_LICENCE_CRI_ID);
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

            List<VcStatusDto> currentVcStatuses = ipvSessionItem.getCurrentVcStatuses();

            List<VisitedCredentialIssuerDetailsDto> visitedCredentialIssuers =
                    ipvSessionItem.getVisitedCredentialIssuerDetails();

            String userId = ipvSessionItem.getClientSessionDetails().getUserId();

            JourneyResponse response;
            if (shouldSendUserToApp(userId)) {
                response =
                        getNextAppJourneyCri(visitedCredentialIssuers, currentVcStatuses, userId);
            } else {
                response =
                        getNextWebJourneyCri(visitedCredentialIssuers, currentVcStatuses, userId);
            }

            var message =
                    new StringMapMessage()
                            .with("lambdaResult", "Successfully found next step for user")
                            .with("journeyResponse", response.getJourney());
            LOGGER.info(message);

            return ApiGatewayResponseGenerator.proxyJsonResponse(HttpStatus.SC_OK, response);
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

    private JourneyResponse getNextWebJourneyCri(
            List<VisitedCredentialIssuerDetailsDto> visitedCredentialIssuers,
            List<VcStatusDto> currentVcStatuses,
            String userId)
            throws ParseException {
        Optional<JourneyResponse> passportResponse =
                getCriResponse(
                        visitedCredentialIssuers,
                        currentVcStatuses,
                        passportCriId,
                        passportCriId,
                        userId);
        Optional<JourneyResponse> drivingLicenceResponse =
                getCriResponse(
                        visitedCredentialIssuers,
                        currentVcStatuses,
                        drivingLicenceCriId,
                        drivingLicenceCriId,
                        userId);
        if (passportResponse.isPresent() && drivingLicenceResponse.isPresent()) {
            if (userHasVisited(visitedCredentialIssuers, drivingLicenceCriId)) {
                return drivingLicenceResponse.get();
            }
            return passportResponse.get();
        }

        Optional<JourneyResponse> addressResponse =
                getCriResponse(
                        visitedCredentialIssuers,
                        currentVcStatuses,
                        addressCriId,
                        addressCriId,
                        userId);
        if (addressResponse.isPresent()) {
            return addressResponse.get();
        }

        Optional<JourneyResponse> fraudResponse =
                getCriResponse(
                        visitedCredentialIssuers,
                        currentVcStatuses,
                        fraudCriId,
                        fraudCriId,
                        userId);
        if (fraudResponse.isPresent()) {
            return fraudResponse.get();
        }

        Optional<JourneyResponse> kbvResponse =
                getCriResponse(
                        visitedCredentialIssuers, currentVcStatuses, kbvCriId, kbvCriId, userId);
        if (kbvResponse.isPresent()) {
            return kbvResponse.get();
        }

        LOGGER.info("Unable to determine next credential issuer");
        return new JourneyResponse(JOURNEY_FAIL);
    }

    private JourneyResponse getNextAppJourneyCri(
            List<VisitedCredentialIssuerDetailsDto> visitedCredentialIssuers,
            List<VcStatusDto> currentVcStatuses,
            String userId)
            throws ParseException {
        Optional<JourneyResponse> dcmawResponse =
                getCriResponse(
                        visitedCredentialIssuers,
                        currentVcStatuses,
                        dcmawCriId,
                        dcmawCriId,
                        userId);
        if (dcmawResponse.isPresent()) {
            return dcmawResponse.get();
        }

        Optional<JourneyResponse> addressResponse =
                getCriResponse(
                        visitedCredentialIssuers,
                        currentVcStatuses,
                        addressCriId,
                        DCMAW_SUCCESS_PAGE,
                        userId);
        if (addressResponse.isPresent()) {
            return addressResponse.get();
        }

        Optional<JourneyResponse> fraudResponse =
                getCriResponse(
                        visitedCredentialIssuers,
                        currentVcStatuses,
                        fraudCriId,
                        fraudCriId,
                        userId);
        if (fraudResponse.isPresent()) {
            return fraudResponse.get();
        }

        LOGGER.info("Unable to determine next credential issuer");
        return new JourneyResponse(JOURNEY_FAIL);
    }

    private void logGovUkSignInJourneyId(String ipvSessionId) {
        IpvSessionItem ipvSessionItem = ipvSessionService.getIpvSession(ipvSessionId);
        ClientSessionDetailsDto clientSessionDetailsDto = ipvSessionItem.getClientSessionDetails();
        LogHelper.attachGovukSigninJourneyIdToLogs(
                clientSessionDetailsDto.getGovukSigninJourneyId());
    }

    private JourneyResponse getJourneyResponse(String criId) {
        return new JourneyResponse(String.format(CRI_START_JOURNEY, criId));
    }

    private JourneyResponse getJourneyPyiNoMatchResponse() {
        return new JourneyResponse("/journey/pyi-no-match");
    }

    private JourneyResponse getJourneyKbvFailResponse() {
        return new JourneyResponse("/journey/pyi-kbv-thin-file");
    }

    private Optional<JourneyResponse> getCriResponse(
            List<VisitedCredentialIssuerDetailsDto> visitedCredentialIssuers,
            List<VcStatusDto> currentVcStatuses,
            String criId,
            String journeyId,
            String userId)
            throws ParseException {

        CredentialIssuerConfig criConfig = configService.getCredentialIssuer(criId);
        Optional<VcStatusDto> vc = getVc(currentVcStatuses, criConfig.getAudienceForClients());

        if (vc.isEmpty()) {
            if (userHasNotVisited(visitedCredentialIssuers, criId)) {
                if (criId.equals(dcmawCriId)
                        && (hasPassportVc(currentVcStatuses)
                                || hasDrivingLicenceVc(currentVcStatuses))) {
                    LOGGER.info(
                            "User already has a passport or driving licence VC, continuing a web journey");
                    return Optional.of(
                            getNextWebJourneyCri(
                                    visitedCredentialIssuers, currentVcStatuses, userId));
                }

                CredentialIssuerConfig ukDrivingLicenseCriConfig =
                        configService.getCredentialIssuer(drivingLicenceCriId);
                if (criId.equals(passportCriId) && ukDrivingLicenseCriConfig.getEnabled()) {
                    return getMultipleDocCheckPage();
                }

                return Optional.of(getJourneyResponse(journeyId));
            }
            var message =
                    new StringMapMessage()
                            .with(
                                    "description",
                                    "User has a previous failed visit to a cri due to an oauth error")
                            .with("criId", criId);
            LOGGER.info(message);

            return Optional.of(
                    criId.equals(dcmawCriId)
                            ? getNextWebJourneyCri(
                                    visitedCredentialIssuers, currentVcStatuses, userId)
                            : getJourneyPyiNoMatchResponse());
        }

        if (Boolean.FALSE.equals(vc.get().getIsSuccessfulVc())) {
            var message =
                    new StringMapMessage()
                            .with(
                                    "description",
                                    "User has a previous failed visit to a cri due to a failed identity check")
                            .with("criId", criId);
            LOGGER.info(message);

            if (criId.equals(dcmawCriId)) {
                LOGGER.info("Reverting app user to the web journey");
                return Optional.of(
                        getNextWebJourneyCri(visitedCredentialIssuers, currentVcStatuses, userId));
            } else if (criId.equals(kbvCriId)) {
                return Optional.of(getJourneyKbvFailResponse());
            }
            return Optional.of(getJourneyPyiNoMatchResponse());
        }
        return Optional.empty();
    }

    private Optional<JourneyResponse> getMultipleDocCheckPage() {
        if (drivingLicenceCriId.startsWith("stub")) {
            return Optional.of(getJourneyResponse(STUB_UK_PASSPORT_AND_DRIVING_LICENCE_PAGE));
        }
        return Optional.of(getJourneyResponse(UK_PASSPORT_AND_DRIVING_LICENCE_PAGE));
    }

    private boolean hasPassportVc(List<VcStatusDto> currentVcStatuses) {
        CredentialIssuerConfig passportConfig = configService.getCredentialIssuer(passportCriId);
        Optional<VcStatusDto> passportVc =
                getVc(currentVcStatuses, passportConfig.getAudienceForClients());
        return passportVc.isPresent();
    }

    private boolean hasDrivingLicenceVc(List<VcStatusDto> currentVcStatuses) {
        CredentialIssuerConfig drivingLicenceConfig =
                configService.getCredentialIssuer(drivingLicenceCriId);
        Optional<VcStatusDto> drivingLicenceVc =
                getVc(currentVcStatuses, drivingLicenceConfig.getAudienceForClients());
        return drivingLicenceVc.isPresent();
    }

    private Optional<VcStatusDto> getVc(List<VcStatusDto> currentVcStatuses, String criIss) {
        if (currentVcStatuses != null) {
            return currentVcStatuses.stream()
                    .filter(vcStatusDto -> vcStatusDto.getCriIss().equals(criIss))
                    .findFirst();
        }
        return Optional.empty();
    }

    private boolean userHasNotVisited(
            List<VisitedCredentialIssuerDetailsDto> visitedCredentialIssuers, String criId) {
        return visitedCredentialIssuers.stream().noneMatch(cri -> cri.getCriId().equals(criId));
    }

    private boolean userHasVisited(
            List<VisitedCredentialIssuerDetailsDto> visitedCredentialIssuers, String criId) {
        return visitedCredentialIssuers.stream().anyMatch(cri -> cri.getCriId().equals(criId));
    }

    private boolean shouldSendUserToApp(String userId) {
        boolean dcmawEnabled = Boolean.parseBoolean(configService.getSsmParameter(DCMAW_ENABLED));
        if (dcmawEnabled) {
            boolean shouldSendAllUsers =
                    Boolean.parseBoolean(
                            configService.getSsmParameter(DCMAW_SHOULD_SEND_ALL_USERS));
            if (!shouldSendAllUsers) {
                if (userId.startsWith(APP_JOURNEY_USER_ID_PREFIX)) {
                    return true;
                }
                String userIds = configService.getSsmParameter(DCMAW_ALLOWED_USER_IDS);
                List<String> dcmawAllowedUserIds = Arrays.asList(userIds.split(","));
                return dcmawAllowedUserIds.contains(userId);
            }
            return true;
        } else {
            return false;
        }
    }
}
