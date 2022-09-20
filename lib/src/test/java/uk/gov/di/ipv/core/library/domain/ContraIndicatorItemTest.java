package uk.gov.di.ipv.core.library.domain;

import org.junit.jupiter.api.Test;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;

class ContraIndicatorItemTest {
    @Test
    void canBeSortedByIssuedAt() {
        ContraIndicatorItem item1 =
                new ContraIndicatorItem(
                        "userId", "sortKey", "issuer", "2022-09-20T07:00:00.000Z", "ci", "ttl");
        ContraIndicatorItem item1Again =
                new ContraIndicatorItem(
                        "userId", "sortKey", "issuer", "2022-09-20T07:00:00.000Z", "ci", "ttl");
        ContraIndicatorItem item2 =
                new ContraIndicatorItem(
                        "userId", "sortKey", "issuer", "2022-09-20T08:00:00.000Z", "ci", "ttl");
        ContraIndicatorItem item3 =
                new ContraIndicatorItem(
                        "userId", "sortKey", "issuer", "2022-09-20T06:00:00.000Z", "ci", "ttl");

        ArrayList<ContraIndicatorItem> toSort =
                new ArrayList<>(List.of(item1, item2, item1Again, item3));

        Collections.sort(toSort);

        assertEquals(List.of(item3, item1, item1Again, item2), toSort);
    }
}
