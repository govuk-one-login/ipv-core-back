package uk.gov.di.ipv.core.library.config;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static uk.gov.di.ipv.core.library.config.CoreFeatureFlag.USE_CONTRA_INDICATOR_VC;

class CoreFeatureFlagTest {
    @Test
    void shouldSetFeatureFlagName() {
        assertEquals("useContraIndicatorVC", USE_CONTRA_INDICATOR_VC.getName());
    }
}
