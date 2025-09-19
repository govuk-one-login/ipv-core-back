package uk.gov.di.ipv.core.library.service;

import org.junit.jupiter.api.Test;
import uk.gov.di.ipv.core.library.config.ConfigurationVariable;
import uk.gov.di.ipv.core.library.domain.Cri;
import uk.gov.di.ipv.core.library.testdata.CommonData;

import java.nio.charset.StandardCharsets;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;

class LocalConfigServiceTest {

    private LocalConfigService getConfigService() throws Exception {
        var parametersYaml =
                new String(
                        CommonData.class
                                .getResourceAsStream("/test-parameters.yaml")
                                .readAllBytes(),
                        StandardCharsets.UTF_8);
        var secretsYaml =
                new String(
                        LocalConfigServiceTest.class
                                .getResourceAsStream("/test-secrets.yaml")
                                .readAllBytes(),
                        StandardCharsets.UTF_8);

        return new LocalConfigService(parametersYaml, secretsYaml);
    }

    @Test
    void getParameterReturnsParameters() throws Exception {
        var configService = getConfigService();

        var param = configService.getComponentId();

        assertEquals("https://identity.local.account.gov.uk", param);
    }

    @Test
    void getParameterReturnsParametersWithFeatureOverride() throws Exception {
        var configService = getConfigService();
        configService.setFeatureSet(List.of("testFeature"));

        var param = configService.getComponentId();

        assertEquals("alternate-component-id", param);
        configService.removeFeatureSet();
    }

    @Test
    void getParameterReturnsParametersWithoutUnrelatedFeatureOverride() throws Exception {
        var configService = getConfigService();
        configService.setFeatureSet(List.of("someOtherFeature"));

        var param = configService.getComponentId();

        assertEquals("https://identity.local.account.gov.uk", param);
        configService.removeFeatureSet();
    }

    @Test
    void getSecretReturnsSecret() throws Exception {
        var configService = getConfigService();

        var secret = configService.getSecret(ConfigurationVariable.EVCS_API_KEY);

        assertEquals("test-api-key", secret);
    }

    @Test
    void shouldReturnIssuerCris() throws Exception {
        var configService = getConfigService();

        assertEquals(
                Cri.NINO,
                configService.getIssuerCris().get("https://nino-cri.stubs.account.gov.uk"));
        assertEquals(
                Cri.EXPERIAN_KBV,
                configService.getIssuerCris().get("https://experian-kbv-cri.stubs.account.gov.uk"));
    }

    @Test
    void removeFeatureSetRemovesThreadLocalFeatureSet() throws Exception {
        var configService = getConfigService();
        var featureSet = List.of("abc", "xyz");

        configService.setFeatureSet(featureSet);
        assertEquals(featureSet, configService.getFeatureSet());

        configService.removeFeatureSet();
        assertNull(configService.getFeatureSet());
    }
}
