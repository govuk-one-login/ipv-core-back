package uk.gov.di.ipv.core.processjourneystep.statemachine.responses;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;

class JourneyContextTest {
    @Test
    void emptyContextReturnsAnEmptyJourneyContext() {
        assertNull(JourneyContext.emptyContext().getFeatureSet());
    }

    @Test
    void withFeatureSetReturnsJourneyContextWithFeatureSet() {
        assertEquals(
                "someFeatureSet", JourneyContext.withFeatureSet("someFeatureSet").getFeatureSet());
    }
}
