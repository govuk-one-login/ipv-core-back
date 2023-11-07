package uk.gov.di.ipv.core.library.config;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static uk.gov.di.ipv.core.library.config.CoreFeatureFlag.UNUSED_PLACEHOLDER;

class CoreFeatureFlagTest {
    @Test
    void shouldSetFeatureFlagName() {
        assertEquals("unusedPlaceHolder", UNUSED_PLACEHOLDER.getName());
    }
}
