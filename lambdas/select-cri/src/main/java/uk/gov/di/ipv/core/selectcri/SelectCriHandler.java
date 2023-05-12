package uk.gov.di.ipv.core.selectcri;

import com.amazonaws.services.lambda.runtime.Context;
import org.apache.http.HttpStatus;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.apache.logging.log4j.message.StringMapMessage;
import software.amazon.lambda.powertools.logging.Logging;
import software.amazon.lambda.powertools.tracing.Tracing;
import uk.gov.di.ipv.core.library.annotations.ExcludeFromGeneratedCoverageReport;
import uk.gov.di.ipv.core.library.domain.ErrorResponse;
import uk.gov.di.ipv.core.library.domain.JourneyErrorResponse;
import uk.gov.di.ipv.core.library.domain.JourneyRequest;
import uk.gov.di.ipv.core.library.domain.JourneyResponse;
import uk.gov.di.ipv.core.library.dto.CredentialIssuerConfig;
import uk.gov.di.ipv.core.library.dto.VcStatusDto;
import uk.gov.di.ipv.core.library.dto.VisitedCredentialIssuerDetailsDto;
import uk.gov.di.ipv.core.library.exceptions.HttpResponseExceptionWithErrorBody;
import uk.gov.di.ipv.core.library.helpers.LogHelper;
import uk.gov.di.ipv.core.library.persistence.item.ClientOAuthSessionItem;
import uk.gov.di.ipv.core.library.persistence.item.IpvSessionItem;
import uk.gov.di.ipv.core.library.service.ClientOAuthSessionDetailsService;
import uk.gov.di.ipv.core.library.service.ConfigService;
import uk.gov.di.ipv.core.library.service.IpvSessionService;
import uk.gov.di.ipv.core.library.statemachine.BaseJourneyLambda;

import java.text.ParseException;
import java.util.Arrays;
import java.util.List;
import java.util.Optional;

import static uk.gov.di.ipv.core.library.config.ConfigurationVariable.DCMAW_ALLOWED_USER_IDS;
import static uk.gov.di.ipv.core.library.config.ConfigurationVariable.DCMAW_SHOULD_SEND_ALL_USERS;
import static uk.gov.di.ipv.core.library.domain.CriConstants.ADDRESS_CRI;
import static uk.gov.di.ipv.core.library.domain.CriConstants.DCMAW_CRI;
import static uk.gov.di.ipv.core.library.domain.CriConstants.DRIVING_LICENCE_CRI;
import static uk.gov.di.ipv.core.library.domain.CriConstants.FRAUD_CRI;
import static uk.gov.di.ipv.core.library.domain.CriConstants.KBV_CRI;
import static uk.gov.di.ipv.core.library.domain.CriConstants.PASSPORT_CRI;
import static uk.gov.di.ipv.core.library.helpers.LogHelper.LogField.LOG_CRI_ID;
import static uk.gov.di.ipv.core.library.helpers.LogHelper.LogField.LOG_LAMBDA_RESULT;
import static uk.gov.di.ipv.core.library.helpers.LogHelper.LogField.LOG_MESSAGE_DESCRIPTION;
import static uk.gov.di.ipv.core.library.helpers.RequestHelper.getIpvSessionId;

public class SelectCriHandler extends BaseJourneyLambda {
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
    private final ClientOAuthSessionDetailsService clientOAuthSessionService;

    public SelectCriHandler(
            ConfigService configService,
            IpvSessionService ipvSessionService,
            ClientOAuthSessionDetailsService clientOAuthSessionService) {
        this.configService = configService;
        this.ipvSessionService = ipvSessionService;
        this.clientOAuthSessionService = clientOAuthSessionService;
    }

    @ExcludeFromGeneratedCoverageReport
    public SelectCriHandler() {
        this.configService = new ConfigService();
        this.ipvSessionService = new IpvSessionService(configService);
        this.clientOAuthSessionService = new ClientOAuthSessionDetailsService(configService);
    }

    @Override
    @Tracing
    @Logging(clearState = true)
    protected JourneyResponse handleRequest(JourneyRequest event, Context context) {
        LogHelper.attachComponentIdToLogs();
        try {
            String ipvSessionId = getIpvSessionId(event);
            IpvSessionItem ipvSessionItem = ipvSessionService.getIpvSession(ipvSessionId);
            ClientOAuthSessionItem clientOAuthSessionItem =
                    clientOAuthSessionService.getClientOAuthSession(
                            ipvSessionItem.getClientOAuthSessionId());

            LogHelper.attachGovukSigninJourneyIdToLogs(
                    clientOAuthSessionItem.getGovukSigninJourneyId());

            List<VcStatusDto> currentVcStatuses = ipvSessionItem.getCurrentVcStatuses();

            List<VisitedCredentialIssuerDetailsDto> visitedCredentialIssuers =
                    ipvSessionItem.getVisitedCredentialIssuerDetails();

            String userId = clientOAuthSessionItem.getUserId();

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
                            .with(
                                    LOG_LAMBDA_RESULT.getFieldName(),
                                    "Successfully found next step for user.")
                            .with("journeyResponse", response.getJourney());
            LOGGER.info(message);

            return response;
        } catch (HttpResponseExceptionWithErrorBody e) {
            LOGGER.error("Received HTTP response exception", e);
            return new JourneyErrorResponse(
                    JOURNEY_ERROR_PATH, e.getResponseCode(), e.getErrorResponse());
        } catch (ParseException e) {
            LOGGER.error("Unable to parse existing credentials", e);
            return new JourneyErrorResponse(
                    JOURNEY_ERROR_PATH,
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
                        PASSPORT_CRI,
                        PASSPORT_CRI,
                        userId);
        Optional<JourneyResponse> drivingLicenceResponse =
                getCriResponse(
                        visitedCredentialIssuers,
                        currentVcStatuses,
                        DRIVING_LICENCE_CRI,
                        DRIVING_LICENCE_CRI,
                        userId);
        if (passportResponse.isPresent() && drivingLicenceResponse.isPresent()) {
            if (userHasVisited(visitedCredentialIssuers, DRIVING_LICENCE_CRI)) {
                return drivingLicenceResponse.get();
            }
            return passportResponse.get();
        }

        Optional<JourneyResponse> addressResponse =
                getCriResponse(
                        visitedCredentialIssuers,
                        currentVcStatuses,
                        ADDRESS_CRI,
                        ADDRESS_CRI,
                        userId);
        if (addressResponse.isPresent()) {
            return addressResponse.get();
        }

        Optional<JourneyResponse> fraudResponse =
                getCriResponse(
                        visitedCredentialIssuers, currentVcStatuses, FRAUD_CRI, FRAUD_CRI, userId);
        if (fraudResponse.isPresent()) {
            return fraudResponse.get();
        }

        Optional<JourneyResponse> kbvResponse =
                getCriResponse(
                        visitedCredentialIssuers, currentVcStatuses, KBV_CRI, KBV_CRI, userId);
        if (kbvResponse.isPresent()) {
            return kbvResponse.get();
        }

        LOGGER.info("Unable to determine next credential issuer.");
        return new JourneyResponse(JOURNEY_FAIL);
    }

    private JourneyResponse getNextAppJourneyCri(
            List<VisitedCredentialIssuerDetailsDto> visitedCredentialIssuers,
            List<VcStatusDto> currentVcStatuses,
            String userId)
            throws ParseException {
        Optional<JourneyResponse> dcmawResponse =
                getCriResponse(
                        visitedCredentialIssuers, currentVcStatuses, DCMAW_CRI, DCMAW_CRI, userId);
        if (dcmawResponse.isPresent()) {
            return dcmawResponse.get();
        }

        Optional<JourneyResponse> addressResponse =
                getCriResponse(
                        visitedCredentialIssuers,
                        currentVcStatuses,
                        ADDRESS_CRI,
                        DCMAW_SUCCESS_PAGE,
                        userId);
        if (addressResponse.isPresent()) {
            return addressResponse.get();
        }

        Optional<JourneyResponse> fraudResponse =
                getCriResponse(
                        visitedCredentialIssuers, currentVcStatuses, FRAUD_CRI, FRAUD_CRI, userId);
        if (fraudResponse.isPresent()) {
            return fraudResponse.get();
        }

        LOGGER.info("Unable to determine next credential issuer.");
        return new JourneyResponse(JOURNEY_FAIL);
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

        CredentialIssuerConfig criConfig =
                configService.getCredentialIssuerActiveConnectionConfig(criId);
        Optional<VcStatusDto> vc = getVc(currentVcStatuses, criConfig.getComponentId());

        if (vc.isEmpty()) {
            if (userHasNotVisited(visitedCredentialIssuers, criId)) {
                if (criId.equals(DCMAW_CRI)
                        && (hasPassportVc(currentVcStatuses)
                                || hasDrivingLicenceVc(currentVcStatuses))) {
                    LOGGER.info(
                            "User already has a passport or driving licence VC, continuing a web journey.");
                    return Optional.of(
                            getNextWebJourneyCri(
                                    visitedCredentialIssuers, currentVcStatuses, userId));
                }

                if (criId.equals(PASSPORT_CRI) && configService.isEnabled(DRIVING_LICENCE_CRI)) {
                    return getMultipleDocCheckPage();
                }

                return Optional.of(getJourneyResponse(journeyId));
            }
            var message =
                    new StringMapMessage()
                            .with(
                                    LOG_MESSAGE_DESCRIPTION.getFieldName(),
                                    "User has a previous failed visit to a cri due to an oauth error.")
                            .with(LOG_CRI_ID.getFieldName(), criId);
            LOGGER.info(message);

            return Optional.of(
                    criId.equals(DCMAW_CRI)
                            ? getNextWebJourneyCri(
                                    visitedCredentialIssuers, currentVcStatuses, userId)
                            : getJourneyPyiNoMatchResponse());
        }

        if (Boolean.FALSE.equals(vc.get().getIsSuccessfulVc())) {
            var message =
                    new StringMapMessage()
                            .with(
                                    LOG_MESSAGE_DESCRIPTION.getFieldName(),
                                    "User has a previous failed visit to a cri due to a failed identity check.")
                            .with(LOG_CRI_ID.getFieldName(), criId);
            LOGGER.info(message);

            if (criId.equals(DCMAW_CRI)) {
                LOGGER.info("Reverting app user to the web journey.");
                return Optional.of(
                        getNextWebJourneyCri(visitedCredentialIssuers, currentVcStatuses, userId));
            } else if (criId.equals(KBV_CRI)) {
                return Optional.of(getJourneyKbvFailResponse());
            }
            return Optional.of(getJourneyPyiNoMatchResponse());
        }
        return Optional.empty();
    }

    private Optional<JourneyResponse> getMultipleDocCheckPage() {
        if (configService.getActiveConnection(DRIVING_LICENCE_CRI).equals("stub")) {
            return Optional.of(getJourneyResponse(STUB_UK_PASSPORT_AND_DRIVING_LICENCE_PAGE));
        }
        return Optional.of(getJourneyResponse(UK_PASSPORT_AND_DRIVING_LICENCE_PAGE));
    }

    private boolean hasPassportVc(List<VcStatusDto> currentVcStatuses) {
        CredentialIssuerConfig passportConfig =
                configService.getCredentialIssuerActiveConnectionConfig(PASSPORT_CRI);
        Optional<VcStatusDto> passportVc =
                getVc(currentVcStatuses, passportConfig.getComponentId());
        return passportVc.isPresent();
    }

    private boolean hasDrivingLicenceVc(List<VcStatusDto> currentVcStatuses) {
        CredentialIssuerConfig drivingLicenceConfig =
                configService.getCredentialIssuerActiveConnectionConfig(DRIVING_LICENCE_CRI);
        Optional<VcStatusDto> drivingLicenceVc =
                getVc(currentVcStatuses, drivingLicenceConfig.getComponentId());
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
        boolean dcmawEnabled = configService.isEnabled(DCMAW_CRI);
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
