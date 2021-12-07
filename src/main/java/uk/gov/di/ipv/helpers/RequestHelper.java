package uk.gov.di.ipv.helpers;

import com.amazonaws.services.lambda.runtime.events.APIGatewayProxyRequestEvent;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.nimbusds.oauth2.sdk.util.StringUtils;
import org.apache.http.NameValuePair;
import org.apache.http.client.utils.URLEncodedUtils;

import java.nio.charset.Charset;
import java.util.HashMap;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;
import java.util.stream.Collectors;

public class RequestHelper {

    public static final String IPV_SESSION_ID_HEADER = "ipv-session-id";

    private RequestHelper() {}

    public static <T> T convertRequest(APIGatewayProxyRequestEvent request, Class<T> type) {
        Map<String, String> map = parseRequestBody(request.getBody());
        getHeader(request.getHeaders(), IPV_SESSION_ID_HEADER)
                .ifPresent(h -> map.put("ipv_session_id", h));
        ObjectMapper objectMapper = new ObjectMapper();
        return objectMapper.convertValue(map, type);
    }

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
}
