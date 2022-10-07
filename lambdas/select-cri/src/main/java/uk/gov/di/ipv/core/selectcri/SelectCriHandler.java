package uk.gov.di.ipv.core.selectcri;

import com.amazonaws.services.lambda.runtime.Context;
import com.amazonaws.services.lambda.runtime.RequestHandler;
import com.amazonaws.services.lambda.runtime.events.APIGatewayProxyRequestEvent;
import com.amazonaws.services.lambda.runtime.events.APIGatewayProxyResponseEvent;
import org.apache.http.HttpStatus;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.apache.logging.log4j.message.MapMessage;
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
import uk.gov.di.ipv.core.library.service.ConfigurationService;
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
import static uk.gov.di.ipv.core.library.config.ConfigurationVariable.FRAUD_CRI_ID;
import static uk.gov.di.ipv.core.library.config.ConfigurationVariable.KBV_CRI_ID;
import static uk.gov.di.ipv.core.library.config.ConfigurationVariable.PASSPORT_CRI_ID;

public class SelectCriHandler
        implements RequestHandler<APIGatewayProxyRequestEvent, APIGatewayProxyResponseEvent> {
    private static final Logger LOGGER = LogManager.getLogger();
    private static final String CRI_START_JOURNEY = "/journey/%s";
    public static final String JOURNEY_FAIL = "/journey/fail";
    public static final String DCMAW_SUCCESS_PAGE = "dcmaw-success";
    public static final String APP_JOURNEY_USER_ID_PREFIX = "urn:uuid:app-journey-user-";

    private final ConfigurationService configurationService;
    private final IpvSessionService ipvSessionService;
    private final String passportCriId;
    private final String fraudCriId;
    private final String kbvCriId;
    private final String addressCriId;
    private final String dcmawCriId;

    public SelectCriHandler(
            ConfigurationService configurationService, IpvSessionService ipvSessionService) {
        this.configurationService = configurationService;
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
                    new MapMessage()
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
        if (passportResponse.isPresent()) {
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
        CredentialIssuerConfig criConfig = configurationService.getCredentialIssuer(criId);

        Optional<VcStatusDto> vc = getVc(currentVcStatuses, criConfig.getAudienceForClients());
        if (vc.isEmpty()) {
            if (userHasNotVisited(visitedCredentialIssuers, criId)) {
                return Optional.of(getJourneyResponse(journeyId));
            }
            var message =
                    new MapMessage()
                            .with(
                                    "message",
                                    "User has a previous failed visit to a cri due to an oauth error")
                            .with("criId", criId);
            LOGGER.info(message);

            if (criId.equals(dcmawCriId)) {
                LOGGER.info("Reverting app user to the web journey");
                return Optional.of(
                        getNextWebJourneyCri(visitedCredentialIssuers, currentVcStatuses, userId));
            }

            return Optional.of(getJourneyPyiNoMatchResponse());
        } else if (Boolean.FALSE.equals(vc.get().getIsSuccessfulVc())) {
            var message =
                    new MapMessage()
                            .with(
                                    "message",
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

    private boolean shouldSendUserToApp(String userId) {
        boolean dcmawEnabled =
                Boolean.parseBoolean(configurationService.getSsmParameter(DCMAW_ENABLED));
        if (dcmawEnabled) {
            boolean shouldSendAllUsers =
                    Boolean.parseBoolean(
                            configurationService.getSsmParameter(DCMAW_SHOULD_SEND_ALL_USERS));
            if (!shouldSendAllUsers) {
                if (userId.startsWith(APP_JOURNEY_USER_ID_PREFIX)) {
                    return true;
                }
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
