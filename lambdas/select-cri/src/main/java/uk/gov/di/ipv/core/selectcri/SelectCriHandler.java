package uk.gov.di.ipv.core.selectcri;

import com.amazonaws.services.lambda.runtime.Context;
import com.amazonaws.services.lambda.runtime.RequestHandler;
import org.apache.http.HttpStatus;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import software.amazon.lambda.powertools.logging.Logging;
import software.amazon.lambda.powertools.tracing.Tracing;
import uk.gov.di.ipv.core.library.annotations.ExcludeFromGeneratedCoverageReport;
import uk.gov.di.ipv.core.library.domain.ErrorResponse;
import uk.gov.di.ipv.core.library.dto.ClientSessionDetailsDto;
import uk.gov.di.ipv.core.library.dto.CredentialIssuerConfig;
import uk.gov.di.ipv.core.library.dto.VcStatusDto;
import uk.gov.di.ipv.core.library.dto.VisitedCredentialIssuerDetailsDto;
import uk.gov.di.ipv.core.library.exceptions.HttpResponseExceptionWithErrorBody;
import uk.gov.di.ipv.core.library.helpers.LogHelper;
import uk.gov.di.ipv.core.library.helpers.StepFunctionHelpers;
import uk.gov.di.ipv.core.library.persistence.item.IpvSessionItem;
import uk.gov.di.ipv.core.library.service.ConfigurationService;
import uk.gov.di.ipv.core.library.service.IpvSessionService;

import java.text.ParseException;
import java.util.Arrays;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;

import static uk.gov.di.ipv.core.library.config.ConfigurationVariable.ADDRESS_CRI_ID;
import static uk.gov.di.ipv.core.library.config.ConfigurationVariable.DCMAW_ALLOWED_USER_IDS;
import static uk.gov.di.ipv.core.library.config.ConfigurationVariable.DCMAW_CRI_ID;
import static uk.gov.di.ipv.core.library.config.ConfigurationVariable.DCMAW_ENABLED;
import static uk.gov.di.ipv.core.library.config.ConfigurationVariable.DCMAW_SHOULD_SEND_ALL_USERS;
import static uk.gov.di.ipv.core.library.config.ConfigurationVariable.FRAUD_CRI_ID;
import static uk.gov.di.ipv.core.library.config.ConfigurationVariable.KBV_CRI_ID;
import static uk.gov.di.ipv.core.library.config.ConfigurationVariable.PASSPORT_CRI_ID;
import static uk.gov.di.ipv.core.library.helpers.StepFunctionHelpers.IPV_SESSION_ID;
import static uk.gov.di.ipv.core.library.helpers.StepFunctionHelpers.JOURNEY;

public class SelectCriHandler implements RequestHandler<Map<String, String>, Map<String, Object>> {
    private static final Logger LOGGER = LogManager.getLogger();
    private static final String CRI_START_JOURNEY = "/journey/%s";
    public static final String JOURNEY_FAIL = "/journey/fail";
    public static final String DCMAW_SUCCESS_PAGE = "dcmaw-success";
    public static final String APP_JOURNEY_USER_ID_PREFIX = "urn:uuid:app-journey-user-";
    public static final String JOURNEY_PYI_NO_MATCH = "/journey/pyi-no-match";
    public static final String JOURNEY_PYI_KBV_FAIL = "/journey/pyi-kbv-fail";

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
    @Logging(clearState = true, logEvent = true)
    public Map<String, Object> handleRequest(Map<String, String> input, Context context) {
        LogHelper.attachComponentIdToLogs();
        try {
            String ipvSessionId = StepFunctionHelpers.getIpvSessionId(input);
            IpvSessionItem ipvSessionItem = ipvSessionService.getIpvSession(ipvSessionId);

            logGovUkSignInJourneyId(ipvSessionId);

            List<VcStatusDto> currentVcStatuses = ipvSessionItem.getCurrentVcStatuses();

            List<VisitedCredentialIssuerDetailsDto> visitedCredentialIssuers =
                    ipvSessionItem.getVisitedCredentialIssuerDetails();

            String userId = ipvSessionItem.getClientSessionDetails().getUserId();

            if (shouldSendUserToApp(userId)) {
                Map<String, Object> output =
                        new HashMap<>(
                                getNextAppJourneyCri(
                                        visitedCredentialIssuers,
                                        currentVcStatuses,
                                        userId,
                                        ipvSessionId));
                output.put(IPV_SESSION_ID, ipvSessionId);

                return output;
            } else {
                Map<String, Object> output =
                        new HashMap<>(
                                getNextWebJourneyCri(
                                        visitedCredentialIssuers,
                                        currentVcStatuses,
                                        userId,
                                        ipvSessionId));
                output.put(IPV_SESSION_ID, ipvSessionId);

                return output;
            }
        } catch (HttpResponseExceptionWithErrorBody e) {
            return StepFunctionHelpers.generateErrorOutputMap(
                    e.getResponseCode(), e.getErrorResponse());
        } catch (ParseException e) {
            LOGGER.error("Unable to parse existing credentials", e);
            return StepFunctionHelpers.generateErrorOutputMap(
                    HttpStatus.SC_INTERNAL_SERVER_ERROR,
                    ErrorResponse.FAILED_TO_PARSE_ISSUED_CREDENTIALS);
        }
    }

    private Map<String, Object> getNextWebJourneyCri(
            List<VisitedCredentialIssuerDetailsDto> visitedCredentialIssuers,
            List<VcStatusDto> currentVcStatuses,
            String userId,
            String ipvSessionId)
            throws ParseException {
        Optional<Map<String, Object>> passportResponse =
                getCriResponse(
                        visitedCredentialIssuers,
                        currentVcStatuses,
                        passportCriId,
                        userId,
                        ipvSessionId);
        if (passportResponse.isPresent()) {
            return passportResponse.get();
        }

        if (userHasNotVisited(visitedCredentialIssuers, addressCriId)) {
            return getJourneyResponse(addressCriId);
        } else {
            VisitedCredentialIssuerDetailsDto addressVisitDetails =
                    visitedCredentialIssuers.stream()
                            .filter(cri -> cri.getCriId().equals(addressCriId))
                            .findFirst()
                            .orElseThrow();

            if (!addressVisitDetails.isReturnedWithVc()) {
                LOGGER.info(
                        "User has a previous failed visit to address cri due to: {}. Routing user to the failed journey route.",
                        addressVisitDetails.getOauthError());
                return getJourneyPyiNoMatchResponse();
            }
        }

        Optional<Map<String, Object>> fraudResponse =
                getCriResponse(
                        visitedCredentialIssuers,
                        currentVcStatuses,
                        fraudCriId,
                        userId,
                        ipvSessionId);
        if (fraudResponse.isPresent()) {
            return fraudResponse.get();
        }

        Optional<Map<String, Object>> kbvResponse =
                getCriResponse(
                        visitedCredentialIssuers,
                        currentVcStatuses,
                        kbvCriId,
                        userId,
                        ipvSessionId);
        if (kbvResponse.isPresent()) {
            return kbvResponse.get();
        }

        LOGGER.info("Unable to determine next credential issuer");
        return Map.of(JOURNEY, JOURNEY_FAIL);
    }

    private Map<String, Object> getNextAppJourneyCri(
            List<VisitedCredentialIssuerDetailsDto> visitedCredentialIssuers,
            List<VcStatusDto> currentVcStatuses,
            String userId,
            String ipvSessionId)
            throws ParseException {
        Optional<Map<String, Object>> dcmawResponse =
                getCriResponse(
                        visitedCredentialIssuers,
                        currentVcStatuses,
                        dcmawCriId,
                        userId,
                        ipvSessionId);
        if (dcmawResponse.isPresent()) {
            return dcmawResponse.get();
        }

        if (userHasNotVisited(visitedCredentialIssuers, addressCriId)) {
            return getJourneyResponse(DCMAW_SUCCESS_PAGE);
        } else {
            Optional<VisitedCredentialIssuerDetailsDto> addressVisitDetails =
                    visitedCredentialIssuers.stream()
                            .filter(cri -> cri.getCriId().equals(addressCriId))
                            .findFirst();

            if (addressVisitDetails.isPresent() && !addressVisitDetails.get().isReturnedWithVc()) {
                LOGGER.info(
                        "User has a previous failed visit to address cri due to: {}. Routing user to the failed journey route.",
                        addressVisitDetails.get().getOauthError());
                return getJourneyPyiNoMatchResponse();
            }
        }

        Optional<Map<String, Object>> fraudResponse =
                getCriResponse(
                        visitedCredentialIssuers,
                        currentVcStatuses,
                        fraudCriId,
                        userId,
                        ipvSessionId);
        if (fraudResponse.isPresent()) {
            return fraudResponse.get();
        }

        LOGGER.info("Unable to determine next credential issuer");
        return Map.of(JOURNEY, JOURNEY_FAIL);
    }

    private void logGovUkSignInJourneyId(String ipvSessionId) {
        IpvSessionItem ipvSessionItem = ipvSessionService.getIpvSession(ipvSessionId);
        ClientSessionDetailsDto clientSessionDetailsDto = ipvSessionItem.getClientSessionDetails();
        LogHelper.attachGovukSigninJourneyIdToLogs(
                clientSessionDetailsDto.getGovukSigninJourneyId());
    }

    private Map<String, Object> getJourneyResponse(String criId) {
        return Map.of(JOURNEY, String.format(CRI_START_JOURNEY, criId));
    }

    private Map<String, Object> getJourneyPyiNoMatchResponse() {
        return Map.of(JOURNEY, JOURNEY_PYI_NO_MATCH);
    }

    private Map<String, Object> getJourneyKbvFailResponse() {
        return Map.of(JOURNEY, JOURNEY_PYI_KBV_FAIL);
    }

    private Optional<Map<String, Object>> getCriResponse(
            List<VisitedCredentialIssuerDetailsDto> visitedCredentialIssuers,
            List<VcStatusDto> currentVcStatuses,
            String criId,
            String userId,
            String ipvSessionId)
            throws ParseException {
        CredentialIssuerConfig criConfig = configurationService.getCredentialIssuer(criId);

        LOGGER.info("CRI config audience value: {}", criConfig.getAudienceForClients());

        Optional<VcStatusDto> vc = getVc(currentVcStatuses, criConfig.getAudienceForClients());
        if (vc.isEmpty()) {
            if (userHasNotVisited(visitedCredentialIssuers, criId)) {
                return Optional.of(getJourneyResponse(criId));
            }

            if (criId.equals(dcmawCriId)) {
                LOGGER.info("Routing user to web journey");
                return Optional.of(
                        getNextWebJourneyCri(
                                visitedCredentialIssuers, currentVcStatuses, userId, ipvSessionId));
            }
        } else if (Boolean.FALSE.equals(vc.get().getIsSuccessfulVc())) {
            LOGGER.info(
                    "User has a previous failed visit to {} cri due to a failed identity check",
                    criId);

            if (criId.equals(dcmawCriId)) {
                LOGGER.info("Routing user to web journey");
                return Optional.of(
                        getNextWebJourneyCri(
                                visitedCredentialIssuers, currentVcStatuses, userId, ipvSessionId));
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
