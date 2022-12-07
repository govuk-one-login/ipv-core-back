package uk.gov.di.ipv.core.library.helpers;

import com.amazonaws.util.StringUtils;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.apache.logging.log4j.message.StringMapMessage;
import software.amazon.lambda.powertools.logging.LoggingUtils;
import uk.gov.di.ipv.core.library.annotations.ExcludeFromGeneratedCoverageReport;

@ExcludeFromGeneratedCoverageReport
public class LogHelper {
    private static final Logger LOGGER = LogManager.getLogger();
    private static final String CORE_COMPONENT_ID = "core";
    public static final String GOVUK_SIGNIN_JOURNEY_ID_DEFAULT_VALUE = "unknown";

    public enum LogField {
        CLIENT_ID_LOG_FIELD("clientId"),
        COMPONENT_ID_LOG_FIELD("componentId"),
        CRI_ID_LOG_FIELD("criId"),
        DYNAMODB_TABLE_NAME("dynamoDbTableName"),
        DYNAMODB_KEY_VALUE("dynamoDbKeyValue"),
        EVIDENCE_TYPE("evidenceType"),
        ERROR_CODE_LOG_FIELD("errorCode"),
        ERROR_DESCRIPTION_LOG_FIELD("errorDescription"),
        GOVUK_SIGNIN_JOURNEY_ID_FIELD("govuk_signin_journey_id"),
        IPV_SESSION_ID_LOG_FIELD("ipvSessionId"),
        JTI_LOG_FIELD("jti"),
        JTI_USED_AT_LOG_FIELD("jtiUsedAt"),
        NUMBER_OF_VCS("numberOfVCs"),
        ERROR("error"),
        PAYLOAD("payload"),
        STATUS_CODE("statusCode");
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

    public static void attachGovukSigninJourneyIdToLogs(String govukSigninJourneyId) {
        if (StringUtils.isNullOrEmpty(govukSigninJourneyId)) {
            attachFieldToLogs(
                    LogField.GOVUK_SIGNIN_JOURNEY_ID_FIELD, GOVUK_SIGNIN_JOURNEY_ID_DEFAULT_VALUE);
        } else {
            attachFieldToLogs(LogField.GOVUK_SIGNIN_JOURNEY_ID_FIELD, govukSigninJourneyId);
        }
    }

    public static void logOauthError(String message, int errorCode, String errorDescription) {
        logOauthError(message, Integer.toString(errorCode), errorDescription);
    }

    public static void logOauthError(String message, String errorCode, String errorDescription) {
        var mapMessage =
                new StringMapMessage()
                        .with(LogField.ERROR_CODE_LOG_FIELD.getFieldName(), errorCode)
                        .with(LogField.ERROR_DESCRIPTION_LOG_FIELD.getFieldName(), errorDescription)
                        .with("description", message);
        LOGGER.error(mapMessage);
    }

    private static void attachFieldToLogs(LogField field, String value) {
        LoggingUtils.appendKey(field.getFieldName(), value);
    }
}
