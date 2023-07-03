package uk.gov.di.ipv.core.library.domain;

import org.junit.jupiter.api.Test;

import java.time.Instant;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

public class ContraIndicatorTest {

    private static final Instant CURRENT_TIME = Instant.now();

    private static final String CODE = "CODE1";
    private static final String DOCUMENT_ID = "DOCID-123";

    private static final List<String> TRANSACTIONS =
            List.of("TRANS1", "TRANS2", "TRANS3", "TRANS4");

    private static final List<Mitigation> MITIGATIONS =
            List.of(
                    Mitigation.builder().code("MTG1").build(),
                    Mitigation.builder().code("MTG2").build());

    private static final ContraIndicator CI =
            ContraIndicator.builder()
                    .code(CODE)
                    .issuanceDate(CURRENT_TIME)
                    .documentId(DOCUMENT_ID)
                    .transactionIds(TRANSACTIONS)
                    .mitigations(MITIGATIONS)
                    .incompleteMitigations(Collections.emptyList())
                    .build();

    @Test
    public void checkGetterMethods() {
        assertEquals(CODE, CI.getCode());
        assertEquals(CURRENT_TIME, CI.getIssuanceDate());
        assertEquals(DOCUMENT_ID, CI.getDocumentId());
        assertEquals(TRANSACTIONS, CI.getTransactionIds());
        assertEquals(MITIGATIONS, CI.getMitigations());
        assertTrue(CI.getIncompleteMitigations().isEmpty());
    }

    @Test
    public void shouldBeCompareAccordingIssuanceDate() {
        ContraIndicator contraIndicator1 =
                CI.toBuilder().issuanceDate(CURRENT_TIME.plusSeconds(20)).build();
        ContraIndicator contraIndicator2 = CI.toBuilder().issuanceDate(CURRENT_TIME).build();
        ContraIndicator contraIndicator3 =
                CI.toBuilder().issuanceDate(CURRENT_TIME.minusSeconds(10)).build();
        ContraIndicator contraIndicator4 = CI.toBuilder().issuanceDate(CURRENT_TIME).build();

        assertEquals(0, contraIndicator2.compareTo(contraIndicator4));
        assertTrue(contraIndicator2.compareTo(contraIndicator1) < 0);
        assertTrue(contraIndicator2.compareTo(contraIndicator3) > 0);
        assertTrue(contraIndicator3.compareTo(contraIndicator1) < 0);
        assertTrue(contraIndicator3.compareTo(contraIndicator2) < 0);

        List<ContraIndicator> contraIndicators =
                new ArrayList<>(
                        List.of(
                                contraIndicator1,
                                contraIndicator2,
                                contraIndicator3,
                                contraIndicator4));
        Collections.sort(contraIndicators);
        assertEquals(
                List.of(contraIndicator3, contraIndicator2, contraIndicator4, contraIndicator1),
                contraIndicators);
    }
}
