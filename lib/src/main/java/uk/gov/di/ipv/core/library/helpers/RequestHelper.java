package uk.gov.di.ipv.core.library.helpers;

import com.amazonaws.services.lambda.runtime.events.APIGatewayProxyRequestEvent;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.nimbusds.oauth2.sdk.util.StringUtils;
import org.apache.http.HttpStatus;
import org.apache.http.NameValuePair;
import org.apache.http.client.utils.URLEncodedUtils;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import uk.gov.di.ipv.core.library.domain.ErrorResponse;
import uk.gov.di.ipv.core.library.exceptions.HttpResponseExceptionWithErrorBody;

import java.nio.charset.Charset;
import java.util.HashMap;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;
import java.util.stream.Collectors;

public class RequestHelper {

    public static final String IPV_SESSION_ID_HEADER = "ipv-session-id";
    public static final String IP_ADDRESS_HEADER = "ip-address";
    private static final ObjectMapper objectMapper = new ObjectMapper();
    private static final Logger LOGGER = LogManager.getLogger();

    private RequestHelper() {}

    public static Map<String, String> parseRequestBody(String body) {
        Map<String, String> queryPairs = new HashMap<>();

        for (NameValuePair pair : URLEncodedUtils.parse(body, Charset.defaultCharset())) {
            queryPairs.put(pair.getName(), pair.getValue());
        }

        return queryPairs;
    }

    public static Optional<String> getHeader(Map<String, String> headers, String headerKey) {
        if (headers == null) {
            return Optional.empty();
        }
        var values =
                headers.entrySet().stream()
                        .filter(e -> headerKey.equalsIgnoreCase(e.getKey()))
                        .map(Map.Entry::getValue)
                        .collect(Collectors.toList());
        if (values.size() == 1) {
            var value = values.get(0);
            if (StringUtils.isNotBlank(value)) {
                return Optional.of(value);
            }
        }
        return Optional.empty();
    }

    public static String getHeaderByKey(Map<String, String> headers, String headerKey) {
        if (Objects.isNull(headers)) {
            return null;
        }
        var values =
                headers.entrySet().stream()
                        .filter(e -> headerKey.equalsIgnoreCase(e.getKey()))
                        .map(Map.Entry::getValue)
                        .collect(Collectors.toList());
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

    public static String getIpAddress(APIGatewayProxyRequestEvent event)
            throws HttpResponseExceptionWithErrorBody {
        return getIpAddress(event.getHeaders());
    }

    public static String getIpvSessionId(Map<String, String> headers)
            throws HttpResponseExceptionWithErrorBody {
        String ipvSessionId = RequestHelper.getHeaderByKey(headers, IPV_SESSION_ID_HEADER);
        if (ipvSessionId == null) {
            LOGGER.error("{} not present in header", IPV_SESSION_ID_HEADER);
            throw new HttpResponseExceptionWithErrorBody(
                    HttpStatus.SC_BAD_REQUEST, ErrorResponse.MISSING_IPV_SESSION_ID);
        }
        LogHelper.attachIpvSessionIdToLogs(ipvSessionId);
        return ipvSessionId;
    }

    public static String getIpAddress(Map<String, String> headers)
            throws HttpResponseExceptionWithErrorBody {
        String ipAddress = RequestHelper.getHeaderByKey(headers, IP_ADDRESS_HEADER);
        if (ipAddress == null) {
            LOGGER.error("{} not present in header", IP_ADDRESS_HEADER);
            throw new HttpResponseExceptionWithErrorBody(
                    HttpStatus.SC_BAD_REQUEST, ErrorResponse.MISSING_IP_ADDRESS);
        }
        return ipAddress;
    }
}
