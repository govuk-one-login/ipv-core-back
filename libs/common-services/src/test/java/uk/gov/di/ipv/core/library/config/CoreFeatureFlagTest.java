package uk.gov.di.ipv.core.library.config;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static uk.gov.di.ipv.core.library.config.CoreFeatureFlag.BUNDLE_CIMIT_VC;

class CoreFeatureFlagTest {
    @Test
    void shouldSetFeatureFlagName() {
        assertEquals("bundleCimitVC", BUNDLE_CIMIT_VC.getName());
    }
}
