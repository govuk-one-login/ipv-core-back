package uk.gov.di.ipv.core.library.helpers;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

class RequestHelperTest {

    Map<String, String> headers =
            Map.of(
                    "foo", "bar",
                    "Foo", "bar",
                    "baz", "bar");

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

    @Test
    void getHeaderShouldReturnEmptyOptionalIfHeadersIsNull() {
        Optional<String> result = RequestHelper.getHeader(null, "someHeader");
        assertTrue(result.isEmpty());
    }

    @Test
    void getHeaderShouldReturnEmptyOptionalIfHeaderValueIsBlank() {
        Map<String, String> blank1 = Map.of("illbeblank", "");
        Map<String, String> blank2 = new HashMap<>();
        blank2.put("illbeblank", null);

        for (Map<String, String> headers : List.of(blank1, blank2)) {
            assertTrue(RequestHelper.getHeader(headers, "illbeblank").isEmpty());
        }
    }

    @Test
    void getHeaderByKeyShouldReturnNullIfHeaderNotFound() {
        assertNull(RequestHelper.getHeaderByKey(Map.of("tome", "toyou"), "ohdearohdear"));
    }
}
