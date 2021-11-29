package uk.gov.di.ipv.helpers;

import com.nimbusds.oauth2.sdk.util.StringUtils;
import org.apache.http.NameValuePair;
import org.apache.http.client.utils.URLEncodedUtils;

import java.nio.charset.Charset;
import java.util.HashMap;
import java.util.Map;
import java.util.Optional;
import java.util.stream.Collectors;

public class RequestHelper {

    public static Map<String, String> parseRequestBody(String body) {
        Map<String, String> query_pairs = new HashMap<>();

        for (NameValuePair pair : URLEncodedUtils.parse(body, Charset.defaultCharset())) {
            query_pairs.put(pair.getName(), pair.getValue());
        }

        return query_pairs;
    }

    public static Optional<String> getHeader(Map<String, String> headers, String headerKey) {
        var values = headers.entrySet().stream()
                .filter(e -> headerKey.equalsIgnoreCase(e.getKey()))
                .map(e -> e.getValue())
                .collect(Collectors.toList());
        if (values.size() == 1) {
            var value = values.get(0);
            if (StringUtils.isNotBlank(value)) {
                return Optional.of(value);
            }
        }
        return Optional.empty();
    }
}
