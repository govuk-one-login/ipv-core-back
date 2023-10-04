package uk.gov.di.ipv.core.library.domain;

import org.junit.jupiter.api.Test;
import uk.gov.di.ipv.core.library.domain.cimitvc.ContraIndicator;
import uk.gov.di.ipv.core.library.domain.cimitvc.Mitigation;

import java.time.Instant;
import java.util.Collections;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

class ContraIndicatorTest {

    private static final String CURRENT_TIME = Instant.now().toString();

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
                    .document(DOCUMENT_ID)
                    .txn(TRANSACTIONS)
                    .mitigation(MITIGATIONS)
                    .incompleteMitigation(Collections.emptyList())
                    .build();

    @Test
    void checkGetterMethods() {
        assertEquals(CODE, CI.getCode());
        assertEquals(CURRENT_TIME, CI.getIssuanceDate());
        assertEquals(DOCUMENT_ID, CI.getDocument());
        assertEquals(TRANSACTIONS, CI.getTxn());
        assertEquals(MITIGATIONS, CI.getMitigation());
        assertTrue(CI.getIncompleteMitigation().isEmpty());
    }
}
