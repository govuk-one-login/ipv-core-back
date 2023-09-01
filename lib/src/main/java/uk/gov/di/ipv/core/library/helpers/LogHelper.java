package uk.gov.di.ipv.core.library.helpers;

import com.amazonaws.util.StringUtils;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.apache.logging.log4j.message.StringMapMessage;
import software.amazon.lambda.powertools.logging.LoggingUtils;
import uk.gov.di.ipv.core.library.annotations.ExcludeFromGeneratedCoverageReport;
import uk.gov.di.ipv.core.library.config.ConfigurationVariable;
import uk.gov.di.ipv.core.library.service.ConfigService;

@ExcludeFromGeneratedCoverageReport
public class LogHelper {
    private static final Logger LOGGER = LogManager.getLogger();
    public static final String GOVUK_SIGNIN_JOURNEY_ID_DEFAULT_VALUE = "unknown";

    public enum LogField {
        LOG_MESSAGE_DESCRIPTION("description"),
        LOG_ERROR_CODE("errorCode"),
        LOG_ERROR_DESCRIPTION("errorDescription"),
        LOG_IPV_SESSION_ID("ipvSessionId"),
        LOG_CLIENT_OAUTH_SESSION_ID("clientOAuthSessionId"),
        LOG_CRI_OAUTH_SESSION_ID("criOAuthSessionId"),
        LOG_CRI_ISSUER("criIssuer"),
        LOG_CLIENT_ID("clientId"),
        LOG_COMPONENT_ID("componentId"),
        LOG_CRI_ID("criId"),
        LOG_LAMBDA_RESULT("lambdaResult"),
        LOG_REDIRECT_URI("redirectUri"),
        DYNAMODB_TABLE_NAME("dynamoDbTableName"),
        DYNAMODB_KEY_VALUE("dynamoDbKeyValue"),
        EVIDENCE_TYPE("evidenceType"),
        LOG_GOVUK_SIGNIN_JOURNEY_ID("govuk_signin_journey_id"),
        LOG_JWT_ALGORITHM("jwtAlgorithm"),
        LOG_JTI("jti"),
        LOG_JTI_USED_AT("jtiUsedAt"),
        LOG_NUMBER_OF_VCS("numberOfVCs"),
        LOG_NO_OF_CI_ITEMS("noOfContraIndicatorItems"),
        LOG_CI_SCORE("ciScore"),
        LOG_RESPONSE_CONTENT_TYPE("responseContentType"),
        LOG_VOT("vot"),
        LOG_PROFILE("profile"),
        LOG_SECRET_ID("secretId"),
        LOG_ACCESS_TOKEN("accessToken"),
        LOG_SHA256_ACCESS_TOKEN("sha256AccessToken"),
        LOG_ERROR_JOURNEY_RESPONSE("errorJourneyResponse"),
        LOG_MITIGATION_JOURNEY_ID("mitigationJourneyId"),
        LOG_MITIGATION_JOURNEY_RESPONSE("mitigationJourneyResponse"),
        LOG_MISSING_HEADER_FIELD("missingHeaderField"),
        LOG_USER_STATE("userState"),
        LOG_JOURNEY_EVENT("journeyEvent"),
        LOG_ERROR("error"),
        LOG_PAYLOAD("payload"),
        LOG_STATUS_CODE("statusCode"),
        LOG_PARAMETER_PATH("parameterPath"),
        LOG_FEATURE_SET("featureSet"),
        LOG_JOURNEY_TYPE("journeyType"),
        LOG_SCORE_TYPE("scoreType");
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

    public static void attachComponentIdToLogs(ConfigService configService) {
        attachFieldToLogs(
                LogField.LOG_COMPONENT_ID,
                configService.getSsmParameter(ConfigurationVariable.COMPONENT_ID));
    }

    public static void attachClientIdToLogs(String clientId) {
        attachFieldToLogs(LogField.LOG_CLIENT_ID, clientId);
    }

    public static void attachCriIdToLogs(String criId) {
        attachFieldToLogs(LogField.LOG_CRI_ID, criId);
    }

    public static void attachIpvSessionIdToLogs(String sessionId) {
        attachFieldToLogs(LogField.LOG_IPV_SESSION_ID, sessionId);
    }

    public static void attachFeatureSetToLogs(String featureSet) {
        attachFieldToLogs(LogField.LOG_FEATURE_SET, featureSet);
    }

    public static void attachClientSessionIdToLogs(String sessionId) {
        attachFieldToLogs(LogField.LOG_CLIENT_OAUTH_SESSION_ID, sessionId);
    }

    public static void attachGovukSigninJourneyIdToLogs(String govukSigninJourneyId) {
        if (StringUtils.isNullOrEmpty(govukSigninJourneyId)) {
            attachFieldToLogs(
                    LogField.LOG_GOVUK_SIGNIN_JOURNEY_ID, GOVUK_SIGNIN_JOURNEY_ID_DEFAULT_VALUE);
        } else {
            attachFieldToLogs(LogField.LOG_GOVUK_SIGNIN_JOURNEY_ID, govukSigninJourneyId);
        }
    }

    public static void logErrorMessage(String message, String errorDescription) {
        logErrMessage(message, null, errorDescription, null);
    }

    public static void logErrorMessage(String message, int errorCode, String errorDescription) {
        logErrMessage(message, Integer.toString(errorCode), errorDescription, null);
    }

    public static void logOauthError(String message, String errorCode, String errorDescription) {
        logErrMessage(message, errorCode, errorDescription, null);
    }

    public static void logCriOauthError(
            String message, String errorCode, String errorDescription, String criId) {
        logErrMessage(message, errorCode, errorDescription, criId);
    }

    private static void logErrMessage(
            String message, String errorCode, String errorDescription, String criId) {
        var mapMessage =
                new StringMapMessage()
                        .with(LogField.LOG_MESSAGE_DESCRIPTION.getFieldName(), message)
                        .with(LogField.LOG_ERROR_DESCRIPTION.getFieldName(), errorDescription);
        if (errorCode != null) mapMessage.with(LogField.LOG_ERROR_CODE.getFieldName(), errorCode);
        if (criId != null) mapMessage.with(LogField.LOG_CRI_ID.getFieldName(), criId);
        LOGGER.error(mapMessage);
    }

    private static void attachFieldToLogs(LogField field, String value) {
        LoggingUtils.appendKey(field.getFieldName(), value);
    }
}
