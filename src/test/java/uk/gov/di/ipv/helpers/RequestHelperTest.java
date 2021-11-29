package uk.gov.di.ipv.helpers;

import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

class RequestHelperTest {

    Map<String, String> headers = Map.of(
            "foo", "bar",
            "Foo", "bar",
            "baz", "bar"
    );

    @ParameterizedTest(name = "with matching header: {0}")
    @ValueSource(strings = {"Baz", "baz"})
    void matchHeaderByDownCasing(String headerName) {
        assertEquals("bar", RequestHelper.getHeader(headers, headerName).get());
    }

    @ParameterizedTest(name = "with non-matching header: {0}")
    @ValueSource(strings = {"boo", "", "foo", "Foo"})
    void noMatchingHeader(String headerName) {
        assertTrue(RequestHelper.getHeader(headers, headerName).isEmpty());
    }
}
