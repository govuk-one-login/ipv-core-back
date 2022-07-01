package uk.gov.di.ipv.core.library.helpers;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import software.amazon.lambda.powertools.logging.LoggingUtils;
import uk.gov.di.ipv.core.library.annotations.ExcludeFromGeneratedCoverageReport;

@ExcludeFromGeneratedCoverageReport
public class LogHelper {
    private static final Logger LOGGER = LogManager.getLogger();
    public static final String CLIENT_ID_LOG_FIELD = "clientId";
    public static final String CRI_ID_LOG_FIELD = "criId";
    public static final String ERROR_CODE_LOG_FIELD = "errorCode";
    public static final String ERROR_DESCRIPTION_LOG_FIELD = "errorDescription";
    public static final String IPV_SESSION_ID_LOG_FIELD = "ipvSessionId";
    public static final String COMPONENT_ID_LOG_FIELD = "componentId";
    public static final String COMPONENT_ID = "core";

    private LogHelper() {
        throw new IllegalStateException("Utility class");
    }

    public static void attachComponentIdToLogs() {
        attachFieldToLogs(COMPONENT_ID_LOG_FIELD, COMPONENT_ID);
    }

    public static void attachClientIdToLogs(String clientId) {
        attachFieldToLogs(CLIENT_ID_LOG_FIELD, clientId);
    }

    public static void attachCriIdToLogs(String criId) {
        attachFieldToLogs(CRI_ID_LOG_FIELD, criId);
    }

    public static void attachIpvSessionIdToLogs(String sessionId) {
        attachFieldToLogs(IPV_SESSION_ID_LOG_FIELD, sessionId);
    }

    public static void logOauthError(String message, String errorCode, String errorDescription) {
        LoggingUtils.appendKey(ERROR_CODE_LOG_FIELD, errorCode);
        LoggingUtils.appendKey(ERROR_DESCRIPTION_LOG_FIELD, errorDescription);
        LOGGER.error(message);
        LoggingUtils.removeKeys(ERROR_CODE_LOG_FIELD, ERROR_DESCRIPTION_LOG_FIELD);
    }

    private static void attachFieldToLogs(String field, String value) {
        LoggingUtils.appendKey(field, value);
        LOGGER.info("{} attached to logs", field);
    }
}
