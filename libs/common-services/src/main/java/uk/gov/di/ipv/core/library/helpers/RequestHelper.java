package uk.gov.di.ipv.core.library.helpers;

import com.amazonaws.services.lambda.runtime.events.APIGatewayProxyRequestEvent;
import com.nimbusds.oauth2.sdk.util.StringUtils;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import uk.gov.di.ipv.core.library.domain.CriJourneyRequest;
import uk.gov.di.ipv.core.library.domain.ErrorResponse;
import uk.gov.di.ipv.core.library.domain.JourneyRequest;
import uk.gov.di.ipv.core.library.domain.ProcessRequest;
import uk.gov.di.ipv.core.library.enums.CandidateIdentityType;
import uk.gov.di.ipv.core.library.enums.CoiCheckType;
import uk.gov.di.ipv.core.library.enums.IdentityType;
import uk.gov.di.ipv.core.library.enums.MobileAppJourneyType;
import uk.gov.di.ipv.core.library.enums.SessionCredentialsResetType;
import uk.gov.di.ipv.core.library.exceptions.HttpResponseExceptionWithErrorBody;
import uk.gov.di.ipv.core.library.exceptions.UnknownCoiCheckTypeException;
import uk.gov.di.ipv.core.library.exceptions.UnknownProcessIdentityTypeException;
import uk.gov.di.ipv.core.library.exceptions.UnknownResetTypeException;

import java.util.Arrays;
import java.util.Collections;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.stream.Stream;

import static com.nimbusds.oauth2.sdk.http.HTTPResponse.SC_BAD_REQUEST;
import static software.amazon.awssdk.utils.StringUtils.isBlank;
import static uk.gov.di.ipv.core.library.domain.ErrorResponse.MISSING_CHECK_TYPE;
import static uk.gov.di.ipv.core.library.domain.ErrorResponse.MISSING_PROCESS_IDENTITY_TYPE;
import static uk.gov.di.ipv.core.library.domain.ErrorResponse.MISSING_RESET_TYPE;

public class RequestHelper {

    public static final String IPV_SESSION_ID_HEADER = "ipv-session-id";
    public static final String IP_ADDRESS_HEADER = "ip-address";
    public static final String ENCODED_DEVICE_INFORMATION_HEADER = "txma-audit-encoded";
    public static final String FEATURE_SET_HEADER = "feature-set";
    public static final String DELETE_ONLY_GPG45_VCS = "deleteOnlyGPG45VCs";
    public static final String IDENTITY_TYPE = "identityType";
    public static final String MOBILE_APP_JOURNEY_TYPE = "mobileAppJourneyType";
    private static final Logger LOGGER = LogManager.getLogger();

    private RequestHelper() {}

    public static String getHeaderByKey(Map<String, String> headers, String headerKey) {
        if (Objects.isNull(headers)) {
            return null;
        }
        var values =
                headers.entrySet().stream()
                        .filter(e -> headerKey.equalsIgnoreCase(e.getKey()))
                        .map(Map.Entry::getValue)
                        .toList();
        if (values.size() == 1) {
            var value = values.get(0);
            if (StringUtils.isNotBlank(value)) {
                return value;
            }
        }
        return null;
    }

    public static String getIpvSessionId(APIGatewayProxyRequestEvent event)
            throws HttpResponseExceptionWithErrorBody {
        return getIpvSessionId(event.getHeaders());
    }

    public static String getIpvSessionId(JourneyRequest event)
            throws HttpResponseExceptionWithErrorBody {
        return getIpvSessionId(event, false);
    }

    public static String getIpvSessionIdAllowMissing(JourneyRequest event)
            throws HttpResponseExceptionWithErrorBody {
        return getIpvSessionId(event, true);
    }

    public static String getIpAddress(APIGatewayProxyRequestEvent event) {
        return getIpAddress(event.getHeaders());
    }

    public static String getEncodedDeviceInformation(APIGatewayProxyRequestEvent event) {
        return RequestHelper.getHeaderByKey(event.getHeaders(), ENCODED_DEVICE_INFORMATION_HEADER);
    }

    public static String getIpAddress(JourneyRequest request) {
        var ipAddress = nullIfBlank(request.getIpAddress());
        validateIpAddress(ipAddress);
        return ipAddress;
    }

    public static String getLanguage(CriJourneyRequest request) {
        var language = nullIfBlank(request.getLanguage());

        if (language == null) {
            LOGGER.warn(LogHelper.buildErrorMessage(ErrorResponse.MISSING_LANGUAGE));
        }

        return language;
    }

    public static String getClientOAuthSessionIdAllowMissing(JourneyRequest event) {
        var clientSessionId = nullIfBlank(event.getClientOAuthSessionId());
        LogHelper.attachClientSessionIdToLogs(clientSessionId);
        return clientSessionId;
    }

    public static List<String> getFeatureSet(JourneyRequest request) {
        var featureSet = nullIfBlank(request.getFeatureSet());
        var featureSetList =
                featureSet != null
                        ? Arrays.asList(featureSet.split(","))
                        : Collections.<String>emptyList();
        LogHelper.attachFeatureSetToLogs(featureSetList);
        return featureSetList;
    }

    public static List<String> getFeatureSet(APIGatewayProxyRequestEvent event) {
        return getFeatureSet(event.getHeaders());
    }

    public static List<String> getFeatureSet(Map<String, String> headers) {
        String featureSetHeaderValue = RequestHelper.getHeaderByKey(headers, FEATURE_SET_HEADER);
        List<String> featureSet =
                (featureSetHeaderValue != null)
                        ? Arrays.asList(featureSetHeaderValue.split(","))
                        : Collections.emptyList();
        LogHelper.attachFeatureSetToLogs(featureSet);
        return featureSet;
    }

    public static String getJourneyEvent(JourneyRequest request)
            throws HttpResponseExceptionWithErrorBody {
        var parts = request.getJourneyUri().getPath().split("/");
        return parts[parts.length - 1];
    }

    public static String getJourneyParameter(JourneyRequest request, String key)
            throws HttpResponseExceptionWithErrorBody {
        return Stream.ofNullable(request.getJourneyUri().getQuery())
                .flatMap(queryString -> Arrays.stream(queryString.split("&")))
                .filter(queryParam -> queryParam.startsWith(String.format("%s=", key)))
                .findFirst()
                .map(queryParam -> queryParam.split("=", 2)[1])
                .filter(StringUtils::isNotBlank)
                .orElse(null);
    }

    public static String getScoreType(ProcessRequest request)
            throws HttpResponseExceptionWithErrorBody {
        return extractValueFromLambdaInput(request, "scoreType", ErrorResponse.MISSING_SCORE_TYPE);
    }

    public static Integer getScoreThreshold(ProcessRequest request)
            throws HttpResponseExceptionWithErrorBody {
        return extractValueFromLambdaInput(
                request, "scoreThreshold", ErrorResponse.MISSING_SCORE_THRESHOLD);
    }

    public static boolean getDeleteOnlyGPG45VCs(ProcessRequest request)
            throws HttpResponseExceptionWithErrorBody {
        return Boolean.TRUE.equals(
                extractValueFromLambdaInput(
                        request,
                        DELETE_ONLY_GPG45_VCS,
                        ErrorResponse.MISSING_IS_RESET_DELETE_GPG45_ONLY_PARAMETER));
    }

    public static IdentityType getIdentityType(ProcessRequest request)
            throws HttpResponseExceptionWithErrorBody {
        String identityType =
                extractValueFromLambdaInput(
                        request, IDENTITY_TYPE, ErrorResponse.INVALID_IDENTITY_TYPE_PARAMETER);
        try {
            return IdentityType.valueOf(identityType.toUpperCase());
        } catch (IllegalArgumentException e) {
            throw new HttpResponseExceptionWithErrorBody(
                    SC_BAD_REQUEST, ErrorResponse.INVALID_IDENTITY_TYPE_PARAMETER);
        }
    }

    public static CoiCheckType getCoiCheckType(ProcessRequest request)
            throws HttpResponseExceptionWithErrorBody, UnknownCoiCheckTypeException {
        String checkType = extractValueFromLambdaInput(request, "checkType", MISSING_CHECK_TYPE);
        try {
            return CoiCheckType.valueOf(checkType);
        } catch (IllegalArgumentException e) {
            throw new UnknownCoiCheckTypeException(checkType);
        }
    }

    public static CandidateIdentityType getProcessIdentityType(ProcessRequest request)
            throws HttpResponseExceptionWithErrorBody, UnknownProcessIdentityTypeException {
        String checkType =
                extractValueFromLambdaInput(request, IDENTITY_TYPE, MISSING_PROCESS_IDENTITY_TYPE);
        try {
            return CandidateIdentityType.valueOf(checkType);
        } catch (IllegalArgumentException e) {
            throw new UnknownProcessIdentityTypeException(checkType);
        }
    }

    public static SessionCredentialsResetType getSessionCredentialsResetType(ProcessRequest request)
            throws HttpResponseExceptionWithErrorBody, UnknownResetTypeException {
        String resetType = extractValueFromLambdaInput(request, "resetType", MISSING_RESET_TYPE);
        try {
            return SessionCredentialsResetType.valueOf(resetType);
        } catch (IllegalArgumentException e) {
            throw new UnknownResetTypeException(resetType);
        }
    }

    public static MobileAppJourneyType getMobileAppJourneyType(ProcessRequest request)
            throws HttpResponseExceptionWithErrorBody {
        String mobileAppJourneyType =
                extractValueFromLambdaInput(
                        request,
                        MOBILE_APP_JOURNEY_TYPE,
                        ErrorResponse.INVALID_PROCESS_MOBILE_APP_JOURNEY_TYPE);
        try {
            return MobileAppJourneyType.valueOf(mobileAppJourneyType.toUpperCase());
        } catch (IllegalArgumentException e) {
            throw new HttpResponseExceptionWithErrorBody(
                    SC_BAD_REQUEST, ErrorResponse.INVALID_PROCESS_MOBILE_APP_JOURNEY_TYPE);
        }
    }

    private static <T> T extractValueFromLambdaInput(
            ProcessRequest request, String key, ErrorResponse errorResponse)
            throws HttpResponseExceptionWithErrorBody {
        Map<String, Object> lambdaInput = request.getLambdaInput();
        if (lambdaInput == null) {
            LOGGER.error(LogHelper.buildLogMessage("Missing lambdaInput map"));
            throw new HttpResponseExceptionWithErrorBody(SC_BAD_REQUEST, errorResponse);
        }
        T value = (T) lambdaInput.get(key);
        if (value == null) {
            LOGGER.error(
                    LogHelper.buildLogMessage(String.format("Missing '%s' in lambdaInput", key)));
            throw new HttpResponseExceptionWithErrorBody(SC_BAD_REQUEST, errorResponse);
        }
        return value;
    }

    private static String getIpvSessionId(Map<String, String> headers)
            throws HttpResponseExceptionWithErrorBody {
        String ipvSessionId = RequestHelper.getHeaderByKey(headers, IPV_SESSION_ID_HEADER);
        String message = String.format("%s not present in header", IPV_SESSION_ID_HEADER);

        validateIpvSessionId(ipvSessionId, message, false);

        LogHelper.attachIpvSessionIdToLogs(ipvSessionId);
        return ipvSessionId;
    }

    private static String getIpvSessionId(JourneyRequest request, boolean allowMissing)
            throws HttpResponseExceptionWithErrorBody {
        var ipvSessionId = nullIfBlank(request.getIpvSessionId());
        validateIpvSessionId(ipvSessionId, "ipvSessionId not present in request", allowMissing);
        LogHelper.attachIpvSessionIdToLogs(ipvSessionId);
        return ipvSessionId;
    }

    private static void validateIpvSessionId(
            String ipvSessionId, String errorMessage, boolean allowMissing)
            throws HttpResponseExceptionWithErrorBody {
        if (isBlank(ipvSessionId)) {
            if (allowMissing) {
                LOGGER.warn(LogHelper.buildLogMessage(errorMessage));
            } else {
                LOGGER.error(LogHelper.buildLogMessage(errorMessage));
                throw new HttpResponseExceptionWithErrorBody(
                        SC_BAD_REQUEST, ErrorResponse.MISSING_IPV_SESSION_ID);
            }
        }
    }

    private static String getIpAddress(Map<String, String> headers) {
        String ipAddress = RequestHelper.getHeaderByKey(headers, IP_ADDRESS_HEADER);
        validateIpAddress(ipAddress);
        return ipAddress;
    }

    private static void validateIpAddress(String ipAddress) {
        if (ipAddress == null) {
            LOGGER.warn(LogHelper.buildErrorMessage(ErrorResponse.MISSING_IP_ADDRESS));
        }
    }

    private static String nullIfBlank(String input) {
        return isBlank(input) ? null : input;
    }
}
