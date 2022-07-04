package uk.gov.di.ipv.core.journeyengine;

import com.amazonaws.services.lambda.runtime.Context;
import com.amazonaws.services.lambda.runtime.RequestHandler;
import com.amazonaws.services.lambda.runtime.events.APIGatewayProxyRequestEvent;
import com.amazonaws.services.lambda.runtime.events.APIGatewayProxyResponseEvent;
import com.nimbusds.oauth2.sdk.OAuth2Error;
import org.apache.http.HttpStatus;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.apache.logging.log4j.message.MapMessage;
import software.amazon.awssdk.utils.StringUtils;
import software.amazon.lambda.powertools.logging.Logging;
import software.amazon.lambda.powertools.tracing.Tracing;
import uk.gov.di.ipv.core.journeyengine.domain.JourneyEngineResult;
import uk.gov.di.ipv.core.journeyengine.domain.JourneyStep;
import uk.gov.di.ipv.core.journeyengine.domain.PageResponse;
import uk.gov.di.ipv.core.journeyengine.exceptions.JourneyEngineException;
import uk.gov.di.ipv.core.library.annotations.ExcludeFromGeneratedCoverageReport;
import uk.gov.di.ipv.core.library.domain.ErrorResponse;
import uk.gov.di.ipv.core.library.domain.JourneyResponse;
import uk.gov.di.ipv.core.library.domain.UserStates;
import uk.gov.di.ipv.core.library.exceptions.HttpResponseExceptionWithErrorBody;
import uk.gov.di.ipv.core.library.helpers.ApiGatewayResponseGenerator;
import uk.gov.di.ipv.core.library.helpers.LogHelper;
import uk.gov.di.ipv.core.library.helpers.RequestHelper;
import uk.gov.di.ipv.core.library.persistence.item.IpvSessionItem;
import uk.gov.di.ipv.core.library.service.ConfigurationService;
import uk.gov.di.ipv.core.library.service.IpvSessionService;

import java.time.Instant;
import java.util.Arrays;
import java.util.Map;
import java.util.Optional;

import static uk.gov.di.ipv.core.journeyengine.domain.JourneyStep.ERROR;
import static uk.gov.di.ipv.core.journeyengine.domain.JourneyStep.FAIL;
import static uk.gov.di.ipv.core.journeyengine.domain.JourneyStep.NEXT;
import static uk.gov.di.ipv.core.library.config.ConfigurationVariable.ADDRESS_CRI_ID;
import static uk.gov.di.ipv.core.library.config.ConfigurationVariable.BACKEND_SESSION_TIMEOUT;
import static uk.gov.di.ipv.core.library.config.ConfigurationVariable.FRAUD_CRI_ID;
import static uk.gov.di.ipv.core.library.config.ConfigurationVariable.KBV_CRI_ID;
import static uk.gov.di.ipv.core.library.config.ConfigurationVariable.PASSPORT_CRI_ID;
import static uk.gov.di.ipv.core.library.config.EnvironmentVariable.IPV_JOURNEY_CRI_START_URI;
import static uk.gov.di.ipv.core.library.config.EnvironmentVariable.IPV_JOURNEY_SESSION_END_URI;
import static uk.gov.di.ipv.core.library.domain.UserStates.CORE_SESSION_TIMEOUT;
import static uk.gov.di.ipv.core.library.domain.UserStates.CRI_ADDRESS;
import static uk.gov.di.ipv.core.library.domain.UserStates.CRI_ERROR;
import static uk.gov.di.ipv.core.library.domain.UserStates.CRI_FRAUD;
import static uk.gov.di.ipv.core.library.domain.UserStates.CRI_KBV;
import static uk.gov.di.ipv.core.library.domain.UserStates.CRI_UK_PASSPORT;
import static uk.gov.di.ipv.core.library.domain.UserStates.DEBUG_PAGE;
import static uk.gov.di.ipv.core.library.domain.UserStates.IPV_IDENTITY_START_PAGE;
import static uk.gov.di.ipv.core.library.domain.UserStates.IPV_SUCCESS_PAGE;
import static uk.gov.di.ipv.core.library.domain.UserStates.PRE_KBV_TRANSITION_PAGE;
import static uk.gov.di.ipv.core.library.domain.UserStates.PYI_KBV_FAIL;
import static uk.gov.di.ipv.core.library.domain.UserStates.PYI_NO_MATCH;
import static uk.gov.di.ipv.core.library.domain.UserStates.PYI_TECHNICAL_ERROR_PAGE;
import static uk.gov.di.ipv.core.library.domain.UserStates.PYI_TECHNICAL_UNRECOVERABLE_ERROR_PAGE;

public class JourneyEngineHandler
        implements RequestHandler<APIGatewayProxyRequestEvent, APIGatewayProxyResponseEvent> {
    private static final Logger LOGGER = LogManager.getLogger();
    private static final String JOURNEY_STEP_PARAM = "journeyStep";

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
    @Logging(clearState = true)
    public APIGatewayProxyResponseEvent handleRequest(
            APIGatewayProxyRequestEvent input, Context context) {
        LogHelper.attachComponentIdToLogs();
        try {
            var ipvSessionId = RequestHelper.getIpvSessionId(input);
            Map<String, String> pathParameters = input.getPathParameters();

            var errorResponse = validate(pathParameters);
            if (errorResponse.isPresent()) {
                return ApiGatewayResponseGenerator.proxyJsonResponse(400, errorResponse.get());
            }

            IpvSessionItem ipvSessionItem = ipvSessionService.getIpvSession(ipvSessionId);

            if (ipvSessionItem == null) {
                LOGGER.warn("Failed to find ipv-session");
                return ApiGatewayResponseGenerator.proxyJsonResponse(
                        HttpStatus.SC_BAD_REQUEST, ErrorResponse.INVALID_SESSION_ID);
            }

            JourneyStep journeyStep =
                    getJourneyStep(input.getPathParameters().get(JOURNEY_STEP_PARAM));

            JourneyEngineResult journeyEngineResult =
                    executeJourneyEvent(journeyStep, ipvSessionItem);

            if (journeyEngineResult.getJourneyResponse() != null) {
                return ApiGatewayResponseGenerator.proxyJsonResponse(
                        HttpStatus.SC_OK, journeyEngineResult.getJourneyResponse());
            } else {
                return ApiGatewayResponseGenerator.proxyJsonResponse(
                        HttpStatus.SC_OK, journeyEngineResult.getPageResponse());
            }
        } catch (HttpResponseExceptionWithErrorBody e) {
            return ApiGatewayResponseGenerator.proxyJsonResponse(
                    e.getResponseCode(), e.getErrorBody());
        } catch (JourneyEngineException e) {
            return ApiGatewayResponseGenerator.proxyJsonResponse(
                    HttpStatus.SC_INTERNAL_SERVER_ERROR, ErrorResponse.FAILED_JOURNEY_ENGINE_STEP);
        }
    }

    @SuppressWarnings("java:S3776") // Cognitive complexity rule
    @Tracing
    private JourneyEngineResult executeJourneyEvent(
            JourneyStep journeyStep, IpvSessionItem ipvSessionItem) throws JourneyEngineException {
        String criStartUri = configurationService.getEnvironmentVariable(IPV_JOURNEY_CRI_START_URI);
        String journeyEndUri =
                configurationService.getEnvironmentVariable(IPV_JOURNEY_SESSION_END_URI);

        String currentUserState = ipvSessionItem.getUserState();
        if (sessionIsNewlyExpired(ipvSessionItem)) {
            updateUserSessionForTimeout(currentUserState, ipvSessionItem);
            return JourneyEngineResult.builder()
                    .pageResponse(new PageResponse(PYI_TECHNICAL_ERROR_PAGE.value))
                    .build();
        }

        try {
            UserStates currentUserStateValue = UserStates.valueOf(currentUserState);

            JourneyEngineResult.JourneyEngineResultBuilder builder = JourneyEngineResult.builder();

            switch (currentUserStateValue) {
                case INITIAL_IPV_JOURNEY:
                    updateUserState(
                            currentUserStateValue,
                            IPV_IDENTITY_START_PAGE,
                            journeyStep,
                            ipvSessionItem);
                    builder.pageResponse(new PageResponse(IPV_IDENTITY_START_PAGE.value));
                    break;
                case IPV_IDENTITY_START_PAGE:
                    updateUserState(
                            currentUserStateValue, CRI_UK_PASSPORT, journeyStep, ipvSessionItem);
                    builder.journeyResponse(
                            new JourneyResponse(
                                    criStartUri
                                            + configurationService.getSsmParameter(
                                                    PASSPORT_CRI_ID)));
                    break;
                case CRI_UK_PASSPORT:
                    if (journeyStep.equals(NEXT)) {
                        updateUserState(
                                currentUserStateValue, CRI_ADDRESS, journeyStep, ipvSessionItem);
                        builder.journeyResponse(
                                new JourneyResponse(
                                        criStartUri
                                                + configurationService.getSsmParameter(
                                                        ADDRESS_CRI_ID)));
                    } else if (journeyStep.equals(ERROR)) {
                        updateUserState(
                                currentUserStateValue, CRI_ERROR, journeyStep, ipvSessionItem);
                        builder.pageResponse(new PageResponse(PYI_TECHNICAL_ERROR_PAGE.value));
                    } else if (journeyStep.equals(FAIL)) {
                        updateUserState(
                                currentUserStateValue, PYI_NO_MATCH, journeyStep, ipvSessionItem);
                        builder.pageResponse(new PageResponse(PYI_NO_MATCH.value));
                    } else {
                        handleInvalidJourneyStep(journeyStep, CRI_UK_PASSPORT.value);
                    }
                    break;
                case CRI_ADDRESS:
                    if (journeyStep.equals(NEXT)) {
                        updateUserState(
                                currentUserStateValue, CRI_FRAUD, journeyStep, ipvSessionItem);
                        builder.journeyResponse(
                                new JourneyResponse(
                                        criStartUri
                                                + configurationService.getSsmParameter(
                                                        FRAUD_CRI_ID)));
                    } else if (journeyStep.equals(ERROR)) {
                        updateUserState(
                                currentUserStateValue, CRI_ERROR, journeyStep, ipvSessionItem);
                        builder.pageResponse(new PageResponse(PYI_TECHNICAL_ERROR_PAGE.value));
                    } else {
                        handleInvalidJourneyStep(journeyStep, CRI_ADDRESS.value);
                    }
                    break;
                case CRI_FRAUD:
                    if (journeyStep.equals(NEXT)) {
                        updateUserState(
                                currentUserStateValue,
                                PRE_KBV_TRANSITION_PAGE,
                                journeyStep,
                                ipvSessionItem);
                        builder.pageResponse(new PageResponse(PRE_KBV_TRANSITION_PAGE.value));
                    } else if (journeyStep.equals(ERROR)) {
                        updateUserState(
                                currentUserStateValue, CRI_ERROR, journeyStep, ipvSessionItem);
                        builder.pageResponse(new PageResponse(PYI_TECHNICAL_ERROR_PAGE.value));
                    } else if (journeyStep.equals(FAIL)) {
                        updateUserState(
                                currentUserStateValue, PYI_NO_MATCH, journeyStep, ipvSessionItem);
                        builder.pageResponse(new PageResponse(PYI_NO_MATCH.value));
                    } else {
                        handleInvalidJourneyStep(journeyStep, CRI_FRAUD.value);
                    }
                    break;
                case PRE_KBV_TRANSITION_PAGE:
                    updateUserState(currentUserStateValue, CRI_KBV, journeyStep, ipvSessionItem);
                    builder.journeyResponse(
                            new JourneyResponse(
                                    criStartUri
                                            + configurationService.getSsmParameter(KBV_CRI_ID)));
                    break;
                case CRI_KBV:
                    if (journeyStep.equals(NEXT)) {
                        updateUserState(
                                currentUserStateValue,
                                IPV_SUCCESS_PAGE,
                                journeyStep,
                                ipvSessionItem);
                        builder.pageResponse(new PageResponse(IPV_SUCCESS_PAGE.value));
                    } else if (journeyStep.equals(ERROR)) {
                        updateUserState(
                                currentUserStateValue, CRI_ERROR, journeyStep, ipvSessionItem);
                        builder.pageResponse(new PageResponse(PYI_TECHNICAL_ERROR_PAGE.value));
                    } else if (journeyStep.equals(FAIL)) {
                        updateUserState(
                                currentUserStateValue, PYI_KBV_FAIL, journeyStep, ipvSessionItem);
                        builder.pageResponse(new PageResponse(PYI_KBV_FAIL.value));
                    } else {
                        handleInvalidJourneyStep(journeyStep, CRI_KBV.value);
                    }
                    break;
                case IPV_SUCCESS_PAGE:
                case PYI_NO_MATCH:
                case PYI_KBV_FAIL:
                case CRI_ERROR:
                case FAILED_CLIENT_JAR:
                case CORE_SESSION_TIMEOUT:
                    builder.journeyResponse(new JourneyResponse(journeyEndUri));
                    break;
                case DEBUG_PAGE:
                    if (journeyStep.equals(NEXT)) {
                        builder.pageResponse(new PageResponse(DEBUG_PAGE.value));
                    } else if (journeyStep.equals(ERROR)) {
                        updateUserState(
                                currentUserStateValue, CRI_ERROR, journeyStep, ipvSessionItem);
                        builder.pageResponse(new PageResponse(PYI_TECHNICAL_ERROR_PAGE.value));
                    } else if (journeyStep.equals(FAIL)) {
                        updateUserState(
                                currentUserStateValue, PYI_NO_MATCH, journeyStep, ipvSessionItem);
                        builder.pageResponse(new PageResponse(PYI_NO_MATCH.value));
                    } else {
                        handleInvalidJourneyStep(journeyStep, DEBUG_PAGE.value);
                    }
                    break;
                default:
                    LOGGER.info("Unknown current user state: {}", currentUserState);
                    updateUserState(currentUserStateValue, CRI_ERROR, journeyStep, ipvSessionItem);
                    builder.pageResponse(
                            new PageResponse(PYI_TECHNICAL_UNRECOVERABLE_ERROR_PAGE.value));
            }

            return builder.build();
        } catch (IllegalArgumentException e) {
            LOGGER.warn("Unknown user state: {}", currentUserState);
            throw new JourneyEngineException(
                    "Unknown user state, failed to execute journey engine step.");
        }
    }

    private JourneyStep getJourneyStep(String journeyStep) throws JourneyEngineException {
        return Arrays.stream(JourneyStep.values())
                .filter(step -> step.toString().equalsIgnoreCase(journeyStep))
                .findFirst()
                .orElseThrow(
                        () -> {
                            LOGGER.warn("Unknown journey step: {}", journeyStep);
                            return new JourneyEngineException(
                                    "Invalid journey step provided, failed to execute journey engine step.");
                        });
    }

    private void handleInvalidJourneyStep(JourneyStep journeyStep, String currentUserState)
            throws JourneyEngineException {
        LOGGER.error(
                "Invalid journey step provided: {} for the current user state: {}",
                journeyStep,
                currentUserState);
        throw new JourneyEngineException(
                String.format(
                        "Invalid journey step provided: %s for the current user status: %s",
                        journeyStep, currentUserState));
    }

    @Tracing
    private void updateUserState(
            UserStates oldState,
            UserStates updatedStateValue,
            JourneyStep journeyStep,
            IpvSessionItem ipvSessionItem) {
        ipvSessionItem.setUserState(updatedStateValue.toString());
        ipvSessionService.updateIpvSession(ipvSessionItem);
        var message =
                new MapMessage()
                        .with("journeyEngine", "State transition")
                        .with("event", journeyStep)
                        .with("from", oldState)
                        .with("to", updatedStateValue);
        LOGGER.info(message);
    }

    @Tracing
    private void updateUserSessionForTimeout(String oldState, IpvSessionItem ipvSessionItem) {
        ipvSessionItem.setErrorCode(OAuth2Error.ACCESS_DENIED.getCode());
        ipvSessionItem.setErrorDescription(OAuth2Error.ACCESS_DENIED.getDescription());
        ipvSessionItem.setUserState(CORE_SESSION_TIMEOUT.toString());
        ipvSessionService.updateIpvSession(ipvSessionItem);
        var message =
                new MapMessage()
                        .with("journeyEngine", "State transition")
                        .with("event", "timeout")
                        .with("from", oldState)
                        .with("to", CORE_SESSION_TIMEOUT.value);
        LOGGER.info(message);
    }

    @Tracing
    private Optional<ErrorResponse> validate(Map<String, String> pathParameters) {
        if (pathParameters.isEmpty()
                || StringUtils.isBlank(pathParameters.get(JOURNEY_STEP_PARAM))) {
            return Optional.of(ErrorResponse.MISSING_JOURNEY_STEP_URL_PATH_PARAM);
        }
        return Optional.empty();
    }

    @Tracing
    private boolean sessionIsNewlyExpired(IpvSessionItem ipvSessionItem) {
        return (!CORE_SESSION_TIMEOUT.toString().equals(ipvSessionItem.getUserState()))
                && Instant.parse(ipvSessionItem.getCreationDateTime())
                        .isBefore(
                                Instant.now()
                                        .minusSeconds(
                                                Long.parseLong(
                                                        configurationService.getSsmParameter(
                                                                BACKEND_SESSION_TIMEOUT))));
    }
}
