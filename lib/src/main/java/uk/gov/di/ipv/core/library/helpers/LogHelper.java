package uk.gov.di.ipv.core.library.helpers;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import software.amazon.lambda.powertools.logging.LoggingUtils;
import uk.gov.di.ipv.core.library.annotations.ExcludeFromGeneratedCoverageReport;

@ExcludeFromGeneratedCoverageReport
public class LogHelper {
    private static final Logger LOGGER = LogManager.getLogger();
    public static final String CORE_COMPONENT_ID = "core";

    public enum LogField {
        CLIENT_ID_LOG_FIELD("clientId"),
        CRI_ID_LOG_FIELD("criId"),
        ERROR_CODE_LOG_FIELD("errorCode"),
        ERROR_DESCRIPTION_LOG_FIELD("errorDescription"),
        IPV_SESSION_ID_LOG_FIELD("ipvSessionId"),
        COMPONENT_ID_LOG_FIELD("componentId"),
        JTI_LOG_FIELD("jti"),
        JTI_USED_AT_LOG_FIELD("jtiUsedAt"),
        DYNAMODB_TABLE_NAME("dynamoDbTableName"),
        DYNAMODB_KEY_VALUE("dynamoDbKeyValue"),
        EVIDENCE_TYPE("evidenceType");
        private final String fieldName;

        LogField(String fieldName) {
            this.fieldName = fieldName;
        }

        public String getFieldName() {
            return fieldName;
        }
    }

    private LogHelper() {
        throw new IllegalStateException("Utility class");
    }

    public static void attachComponentIdToLogs() {
        attachFieldToLogs(LogField.COMPONENT_ID_LOG_FIELD, CORE_COMPONENT_ID);
    }

    public static void attachClientIdToLogs(String clientId) {
        attachFieldToLogs(LogField.CLIENT_ID_LOG_FIELD, clientId);
    }

    public static void attachCriIdToLogs(String criId) {
        attachFieldToLogs(LogField.CRI_ID_LOG_FIELD, criId);
    }

    public static void attachIpvSessionIdToLogs(String sessionId) {
        attachFieldToLogs(LogField.IPV_SESSION_ID_LOG_FIELD, sessionId);
    }

    public static void logOauthError(String message, int errorCode, String errorDescription) {
        logOauthError(message, Integer.toString(errorCode), errorDescription);
    }

    public static void logOauthError(String message, String errorCode, String errorDescription) {
        LoggingUtils.appendKey(LogField.ERROR_CODE_LOG_FIELD.getFieldName(), errorCode);
        LoggingUtils.appendKey(
                LogField.ERROR_DESCRIPTION_LOG_FIELD.getFieldName(), errorDescription);
        LOGGER.error(message);
        LoggingUtils.removeKeys(
                LogField.ERROR_CODE_LOG_FIELD.getFieldName(),
                LogField.ERROR_DESCRIPTION_LOG_FIELD.getFieldName());
    }

    public static void logInfoMessageWithFieldAndValue(
            String message, LogField logField, String logFieldValue) {
        LoggingUtils.appendKey(logField.getFieldName(), logFieldValue);
        LOGGER.info(message);
        LoggingUtils.removeKey(logField.getFieldName());
    }

    private static void attachFieldToLogs(LogField field, String value) {
        LoggingUtils.appendKey(field.getFieldName(), value);
        LOGGER.info("{} attached to logs", field.getFieldName());
    }
}
