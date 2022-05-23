package uk.gov.di.ipv.core.journeyengine;

import com.amazonaws.services.lambda.runtime.Context;
import com.amazonaws.services.lambda.runtime.RequestHandler;
import com.amazonaws.services.lambda.runtime.events.APIGatewayProxyRequestEvent;
import com.amazonaws.services.lambda.runtime.events.APIGatewayProxyResponseEvent;
import org.apache.http.HttpStatus;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import software.amazon.awssdk.utils.StringUtils;
import software.amazon.lambda.powertools.tracing.Tracing;
import uk.gov.di.ipv.core.journeyengine.domain.JourneyEngineResult;
import uk.gov.di.ipv.core.journeyengine.domain.PageResponse;
import uk.gov.di.ipv.core.journeyengine.exceptions.JourneyEngineException;
import uk.gov.di.ipv.core.library.annotations.ExcludeFromGeneratedCoverageReport;
import uk.gov.di.ipv.core.library.domain.ErrorResponse;
import uk.gov.di.ipv.core.library.domain.JourneyResponse;
import uk.gov.di.ipv.core.library.domain.UserStates;
import uk.gov.di.ipv.core.library.helpers.ApiGatewayResponseGenerator;
import uk.gov.di.ipv.core.library.helpers.RequestHelper;
import uk.gov.di.ipv.core.library.persistence.item.IpvSessionItem;
import uk.gov.di.ipv.core.library.service.ConfigurationService;
import uk.gov.di.ipv.core.library.service.IpvSessionService;

import java.util.List;
import java.util.Map;
import java.util.Optional;

import static uk.gov.di.ipv.core.library.domain.UserStates.CRI_ADDRESS;
import static uk.gov.di.ipv.core.library.domain.UserStates.CRI_ERROR;
import static uk.gov.di.ipv.core.library.domain.UserStates.CRI_FRAUD;
import static uk.gov.di.ipv.core.library.domain.UserStates.CRI_KBV;
import static uk.gov.di.ipv.core.library.domain.UserStates.CRI_UK_PASSPORT;
import static uk.gov.di.ipv.core.library.domain.UserStates.DEBUG_PAGE;
import static uk.gov.di.ipv.core.library.domain.UserStates.IPV_ERROR_PAGE;
import static uk.gov.di.ipv.core.library.domain.UserStates.IPV_IDENTITY_START_PAGE;
import static uk.gov.di.ipv.core.library.domain.UserStates.IPV_SUCCESS_PAGE;
import static uk.gov.di.ipv.core.library.domain.UserStates.PRE_KBV_TRANSITION_PAGE;

public class JourneyEngineHandler
        implements RequestHandler<APIGatewayProxyRequestEvent, APIGatewayProxyResponseEvent> {
    private static final Logger LOGGER =
            LoggerFactory.getLogger(JourneyEngineHandler.class.getName());

    private static final String IPV_SESSION_ID_HEADER_KEY = "ipv-session-id";
    private static final String JOURNEY_STEP_PARAM = "journeyStep";
    private static final String NEXT_STEP = "next";
    private static final String ERROR_STEP = "error";
    private static final String UK_PASSPORT_CRI_ID = "ukPassport";
    private static final String ADDRESS_CRI_ID = "address";
    private static final String KBV_CRI_ID = "kbv";
    private static final String FRAUD_CRI_ID = "fraud";

    private static final List<String> VALID_JOURNEY_STEPS = List.of(NEXT_STEP, ERROR_STEP);

    private final IpvSessionService ipvSessionService;
    private final ConfigurationService configurationService;

    public JourneyEngineHandler(
            IpvSessionService ipvSessionService, ConfigurationService configurationService) {
        this.ipvSessionService = ipvSessionService;
        this.configurationService = configurationService;
    }

    @ExcludeFromGeneratedCoverageReport
    public JourneyEngineHandler() {
        this.configurationService = new ConfigurationService();
        this.ipvSessionService = new IpvSessionService(configurationService);
    }

    @Override
    @Tracing
    public APIGatewayProxyResponseEvent handleRequest(
            APIGatewayProxyRequestEvent input, Context context) {

        Map<String, String> pathParameters = input.getPathParameters();

        var errorResponse = validate(pathParameters);
        if (errorResponse.isPresent()) {
            return ApiGatewayResponseGenerator.proxyJsonResponse(400, errorResponse.get());
        }

        String journeyStep = input.getPathParameters().get(JOURNEY_STEP_PARAM);

        var ipvSessionId =
                RequestHelper.getHeaderByKey(input.getHeaders(), IPV_SESSION_ID_HEADER_KEY);

        if (ipvSessionId == null || ipvSessionId.isEmpty()) {
            LOGGER.warn("User credentials could not be retrieved. No session ID received.");
            return ApiGatewayResponseGenerator.proxyJsonResponse(
                    HttpStatus.SC_BAD_REQUEST, ErrorResponse.MISSING_IPV_SESSION_ID);
        }

        IpvSessionItem ipvSessionItem = ipvSessionService.getIpvSession(ipvSessionId);

        if (ipvSessionItem == null) {
            LOGGER.warn("Failed to find ipv-session");
            return ApiGatewayResponseGenerator.proxyJsonResponse(
                    HttpStatus.SC_BAD_REQUEST, ErrorResponse.INVALID_SESSION_ID);
        }
        try {
            JourneyEngineResult journeyEngineResult =
                    executeJourneyEvent(journeyStep, ipvSessionItem);

            if (journeyEngineResult.getJourneyResponse() != null) {
                return ApiGatewayResponseGenerator.proxyJsonResponse(
                        HttpStatus.SC_OK, journeyEngineResult.getJourneyResponse());
            } else {
                return ApiGatewayResponseGenerator.proxyJsonResponse(
                        HttpStatus.SC_OK, journeyEngineResult.getPageResponse());
            }
        } catch (JourneyEngineException e) {
            return ApiGatewayResponseGenerator.proxyJsonResponse(
                    HttpStatus.SC_INTERNAL_SERVER_ERROR, ErrorResponse.FAILED_JOURNEY_ENGINE_STEP);
        }
    }

    @Tracing
    private JourneyEngineResult executeJourneyEvent(
            String journeyStep, IpvSessionItem ipvSessionItem) throws JourneyEngineException {
        String criStartUri = configurationService.getIpvJourneyCriStartUri();
        String journeyEndUri = configurationService.getIpvJourneySessionEnd();

        String currentUserState = ipvSessionItem.getUserState();

        try {
            UserStates currentUserStateValue = UserStates.valueOf(currentUserState);

            JourneyEngineResult.Builder builder = new JourneyEngineResult.Builder();

            if (!VALID_JOURNEY_STEPS.contains(journeyStep)) {
                LOGGER.warn("Unknown journey step: {}", journeyStep);
                throw new JourneyEngineException(
                        "Invalid journey step provided, failed to execute journey engine step.");
            }

            switch (currentUserStateValue) {
                case INITIAL_IPV_JOURNEY:
                    updateUserState(IPV_IDENTITY_START_PAGE, ipvSessionItem);
                    builder.setPageResponse(new PageResponse(IPV_IDENTITY_START_PAGE.value));
                    break;
                case IPV_IDENTITY_START_PAGE:
                    updateUserState(CRI_UK_PASSPORT, ipvSessionItem);
                    builder.setJourneyResponse(
                            new JourneyResponse(criStartUri + UK_PASSPORT_CRI_ID));
                    break;
                case CRI_UK_PASSPORT:
                    if (journeyStep.equals(NEXT_STEP)) {
                        updateUserState(CRI_ADDRESS, ipvSessionItem);
                        builder.setJourneyResponse(
                                new JourneyResponse(criStartUri + ADDRESS_CRI_ID));
                    } else if (journeyStep.equals(ERROR_STEP)) {
                        updateUserState(CRI_ERROR, ipvSessionItem);
                        builder.setPageResponse(new PageResponse(IPV_ERROR_PAGE.value));
                    }
                    break;
                case CRI_ADDRESS:
                    if (journeyStep.equals(NEXT_STEP)) {
                        updateUserState(CRI_FRAUD, ipvSessionItem);
                        builder.setJourneyResponse(new JourneyResponse(criStartUri + FRAUD_CRI_ID));
                    } else if (journeyStep.equals(ERROR_STEP)) {
                        updateUserState(CRI_ERROR, ipvSessionItem);
                        builder.setPageResponse(new PageResponse(IPV_ERROR_PAGE.value));
                    }
                    break;
                case CRI_FRAUD:
                    if (journeyStep.equals(NEXT_STEP)) {
                        updateUserState(PRE_KBV_TRANSITION_PAGE, ipvSessionItem);
                        builder.setPageResponse(new PageResponse(PRE_KBV_TRANSITION_PAGE.value));
                    } else if (journeyStep.equals(ERROR_STEP)) {
                        updateUserState(CRI_ERROR, ipvSessionItem);
                        builder.setPageResponse(new PageResponse(IPV_ERROR_PAGE.value));
                    }
                    break;
                case PRE_KBV_TRANSITION_PAGE:
                    updateUserState(CRI_KBV, ipvSessionItem);
                    builder.setJourneyResponse(new JourneyResponse(criStartUri + KBV_CRI_ID));
                    break;
                case CRI_KBV:
                    if (journeyStep.equals(NEXT_STEP)) {
                        updateUserState(IPV_SUCCESS_PAGE, ipvSessionItem);
                        builder.setPageResponse(new PageResponse(IPV_SUCCESS_PAGE.value));
                    } else if (journeyStep.equals(ERROR_STEP)) {
                        updateUserState(CRI_ERROR, ipvSessionItem);
                        builder.setPageResponse(new PageResponse(IPV_ERROR_PAGE.value));
                    }
                    break;
                case IPV_SUCCESS_PAGE:
                case CRI_ERROR:
                    builder.setJourneyResponse(new JourneyResponse(journeyEndUri));
                    break;
                case DEBUG_PAGE:
                    builder.setPageResponse(new PageResponse(DEBUG_PAGE.value));
                    break;
                default:
                    updateUserState(CRI_ERROR, ipvSessionItem);
                    builder.setPageResponse(new PageResponse(IPV_ERROR_PAGE.value));
            }

            return builder.build();
        } catch (IllegalArgumentException e) {
            LOGGER.warn("Unknown user state: {}", currentUserState);
            throw new JourneyEngineException(
                    "Unknown user state, failed to execute journey engine step.");
        }
    }

    @Tracing
    private void updateUserState(UserStates updatedStateValue, IpvSessionItem previousSessionItem) {
        IpvSessionItem updatedIpvSessionItem = new IpvSessionItem();
        updatedIpvSessionItem.setIpvSessionId(previousSessionItem.getIpvSessionId());
        updatedIpvSessionItem.setCreationDateTime(previousSessionItem.getCreationDateTime());
        updatedIpvSessionItem.setClientSessionDetails(
                previousSessionItem.getClientSessionDetails());
        updatedIpvSessionItem.setUserState(updatedStateValue.toString());

        ipvSessionService.updateIpvSession(updatedIpvSessionItem);
    }

    @Tracing
    private Optional<ErrorResponse> validate(Map<String, String> pathParameters) {
        if (pathParameters.isEmpty()
                || StringUtils.isBlank(pathParameters.get(JOURNEY_STEP_PARAM))) {
            return Optional.of(ErrorResponse.MISSING_JOURNEY_STEP_URL_PATH_PARAM);
        }
        return Optional.empty();
    }
}
