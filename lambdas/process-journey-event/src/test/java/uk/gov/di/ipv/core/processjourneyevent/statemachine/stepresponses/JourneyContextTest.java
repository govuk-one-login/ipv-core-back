package uk.gov.di.ipv.core.processjourneyevent.statemachine.stepresponses;

import org.junit.jupiter.api.Test;

import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;

class JourneyContextTest {
    @Test
    void emptyContextReturnsAnEmptyJourneyContext() {
        assertNull(JourneyContext.emptyContext().getFeatureSet());
    }

    @Test
    void withFeatureSetReturnsJourneyContextWithFeatureSet() {
        List<String> featureSetList = List.of("someFeatureSet");
        assertEquals(featureSetList, JourneyContext.withFeatureSet(featureSetList).getFeatureSet());
    }
}
