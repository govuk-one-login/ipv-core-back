package uk.gov.di.ipv.core.library.helpers;

import com.nimbusds.oauth2.sdk.ErrorObject;
import io.opentelemetry.api.trace.Span;
import org.apache.logging.log4j.message.StringMapMessage;
import software.amazon.awssdk.utils.StringUtils;
import software.amazon.lambda.powertools.logging.LoggingUtils;
import uk.gov.di.ipv.core.library.annotations.ExcludeFromGeneratedCoverageReport;
import uk.gov.di.ipv.core.library.config.ConfigurationVariable;
import uk.gov.di.ipv.core.library.domain.Cri;
import uk.gov.di.ipv.core.library.domain.ErrorResponse;
import uk.gov.di.ipv.core.library.service.ConfigService;

import java.util.List;
import java.util.Objects;

import static uk.gov.di.ipv.core.library.helpers.LogHelper.LogField.LOG_CRI_ID;
import static uk.gov.di.ipv.core.library.helpers.LogHelper.LogField.LOG_ERROR_CODE;
import static uk.gov.di.ipv.core.library.helpers.LogHelper.LogField.LOG_ERROR_DESCRIPTION;
import static uk.gov.di.ipv.core.library.helpers.LogHelper.LogField.LOG_MESSAGE_DESCRIPTION;
import static uk.gov.di.ipv.core.library.helpers.LogHelper.LogField.LOG_QUEUE_NAME;

@ExcludeFromGeneratedCoverageReport
public class LogHelper {
    public static final String GOVUK_SIGNIN_JOURNEY_ID_DEFAULT_VALUE = null;

    public enum LogField {
        LOG_ACCESS_TOKEN("accessToken"),
        LOG_BATCH_ID("batchId"),
        LOG_BIRTH_DATE("birthDate"),
        LOG_CI_SCORE("ciScore"),
        LOG_CLIENT_ID("clientId"),
        LOG_CLIENT_OAUTH_SESSION_ID("clientOAuthSessionId"),
        LOG_COMPONENT_ID("componentId"),
        LOG_CONNECTION("connection"),
        LOG_CONTEXT("context"),
        LOG_CHECK_TYPE("checkType"),
        LOG_COUNT("count"),
        LOG_CRI_ID("criId"),
        LOG_CRI_ISSUER("criIssuer"),
        LOG_CRI_OAUTH_SESSION_ID("criOAuthSessionId"),
        LOG_CRI_RES_RETRIEVED_TYPE("criResourceRetrievedType"),
        LOG_ERROR("error"),
        LOG_ERROR_CODE("errorCode"),
        LOG_ERROR_DESCRIPTION("errorDescription"),
        LOG_ERROR_STACK("errorStack"),
        LOG_ERROR_JOURNEY_RESPONSE("errorJourneyResponse"),
        LOG_FAMILY_NAME("familyName"),
        LOG_FEATURE_SET("featureSet"),
        LOG_GIVEN_NAMES("givenNames"),
        LOG_GOVUK_SIGNIN_JOURNEY_ID("govuk_signin_journey_id"),
        LOG_GPG45_PROFILE("gpg45Profile"),
        LOG_HASH_USER_ID("hashUserId"),
        LOG_IPV_SESSION_ID("ipvSessionId"),
        LOG_IS_VC_SUCCESSFUL("isVCSuccessful"),
        LOG_JWKS_URL("jwksUrl"),
        LOG_JOURNEY_EVENT("journeyEvent"),
        LOG_JOURNEY_RESPONSE("journeyResponse"),
        LOG_JOURNEY_TYPE("journeyType"),
        LOG_JTI("jti"),
        LOG_JTI_USED_AT("jtiUsedAt"),
        LOG_JWT_ALGORITHM("jwtAlgorithm"),
        LOG_KEY_ID("keyId"),
        LOG_LAMBDA_RESULT("lambdaResult"),
        LOG_MESSAGE_DESCRIPTION("description"),
        LOG_MISSING_HEADER_FIELD("missingHeaderField"),
        LOG_MITIGATION_JOURNEY_ID("mitigationJourneyId"),
        LOG_MITIGATION_JOURNEY_RESPONSE("mitigationJourneyResponse"),
        LOG_NO_OF_CI_ITEMS("noOfContraIndicatorItems"),
        LOG_NUMBER_OF_VCS("numberOfVCs"),
        LOG_PARAMETER_PATH("parameterPath"),
        LOG_PAYLOAD("payload"),
        LOG_PROFILE("profile"),
        LOG_QUEUE_NAME("queueName"),
        LOG_SQS_MESSAGE_ID("sqsMessageId"),
        LOG_REDIRECT_URI("redirectUri"),
        LOG_RESET_TYPE("resetType"),
        LOG_RESPONSE_CONTENT_TYPE("responseContentType"),
        LOG_RESPONSE_MESSAGE("responseMessage"),
        LOG_SCOPE("scope"),
        LOG_SCORE_TYPE("scoreType"),
        LOG_SECRET_ID("secretId"),
        LOG_SHA256_ACCESS_TOKEN("sha256AccessToken"),
        LOG_SPAN_ID("dt.span_id"),
        LOG_STATUS_CODE("statusCode"),
        LOG_TRACE_ID("dt.trace_id"),
        LOG_UNCORRELATABLE_DATA("uncorrelatableData"),
        LOG_USER_STATE("userState"),
        LOG_VOT("vot");

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

    public static void attachTraceId() {
        // Adapted from
        // https://docs.dynatrace.com/docs/analyze-explore-automate/logs/lma-log-enrichment#retrieve-span-and-trace-ids
        var spanContext = Span.current().getSpanContext();
        if (spanContext.isValid()) {
            attachFieldToLogs(LogField.LOG_TRACE_ID, spanContext.getTraceId());
            attachFieldToLogs(LogField.LOG_SPAN_ID, spanContext.getSpanId());
        }
    }

    public static void attachComponentId(ConfigService configService) {
        attachFieldToLogs(
                LogField.LOG_COMPONENT_ID,
                configService.getParameter(ConfigurationVariable.COMPONENT_ID));
    }

    public static void attachClientIdToLogs(String clientId) {
        attachFieldToLogs(LogField.LOG_CLIENT_ID, clientId);
    }

    public static void attachCriIdToLogs(Cri cri) {
        attachFieldToLogs(LOG_CRI_ID, cri.getId());
    }

    public static void attachIpvSessionIdToLogs(String sessionId) {
        attachFieldToLogs(LogField.LOG_IPV_SESSION_ID, sessionId);
    }

    public static void attachFeatureSetToLogs(List<String> featureSet) {
        attachFieldToLogs(
                LogField.LOG_FEATURE_SET,
                (featureSet != null) ? String.join(",", featureSet) : null);
    }

    public static void attachClientSessionIdToLogs(String sessionId) {
        attachFieldToLogs(LogField.LOG_CLIENT_OAUTH_SESSION_ID, sessionId);
    }

    public static void attachCriSessionIdToLogs(String sessionId) {
        attachFieldToLogs(LogField.LOG_CRI_OAUTH_SESSION_ID, sessionId);
    }

    public static void attachGovukSigninJourneyIdToLogs(String govukSigninJourneyId) {
        if (StringUtils.isBlank(govukSigninJourneyId)) {
            attachFieldToLogs(
                    LogField.LOG_GOVUK_SIGNIN_JOURNEY_ID, GOVUK_SIGNIN_JOURNEY_ID_DEFAULT_VALUE);
        } else {
            attachFieldToLogs(LogField.LOG_GOVUK_SIGNIN_JOURNEY_ID, govukSigninJourneyId);
        }
    }

    public static void attachQueueNameToLogs(String queueName) {
        if (StringUtils.isBlank(queueName)) {
            LogHelper.attachFieldToLogs(LOG_QUEUE_NAME, "unknown");
        } else {
            LogHelper.attachFieldToLogs(LOG_QUEUE_NAME, queueName);
        }
    }

    public static void attachSqsMessageIdToLogs(String sqsMessageId) {
        var idValue = StringUtils.isBlank(sqsMessageId) ? "unknown" : sqsMessageId;
        attachFieldToLogs(LogField.LOG_SQS_MESSAGE_ID, idValue);
    }

    private static void attachFieldToLogs(LogField field, String value) {
        LoggingUtils.appendKey(field.getFieldName(), value);
    }

    public static StringMapMessage buildLogMessage(String message) {
        return new StringMapMessage().with(LOG_MESSAGE_DESCRIPTION.getFieldName(), message);
    }

    public static StringMapMessage buildErrorMessage(String message, String errorDescription) {
        return buildLogMessage(message)
                .with(
                        LOG_ERROR_DESCRIPTION.getFieldName(),
                        Objects.requireNonNullElse(errorDescription, "Unknown"));
    }

    public static StringMapMessage buildErrorMessage(String message, Exception e) {
        return buildLogMessage(message).with(LOG_ERROR_DESCRIPTION.getFieldName(), e);
    }

    public static StringMapMessage buildErrorMessage(String message, ErrorObject err) {
        return buildErrorMessage(message, err.getDescription(), err.getCode());
    }

    public static StringMapMessage buildErrorMessage(ErrorResponse errorResponse) {
        return buildErrorMessage(
                errorResponse.getMessage(), errorResponse.getMessage(), errorResponse.getCode());
    }

    public static StringMapMessage buildErrorMessage(
            String message, String errorDescription, int errorCode) {
        return buildErrorMessage(message, errorDescription, Integer.toString(errorCode));
    }

    public static StringMapMessage buildErrorMessage(
            String message, String errorDescription, String errorCode) {
        return buildErrorMessage(message, errorDescription)
                .with(
                        LOG_ERROR_CODE.getFieldName(),
                        Objects.requireNonNullElse(errorCode, "Unknown"));
    }
}
