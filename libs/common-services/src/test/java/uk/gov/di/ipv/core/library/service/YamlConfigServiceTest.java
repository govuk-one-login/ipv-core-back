package uk.gov.di.ipv.core.library.service;

import org.junit.jupiter.api.Test;
import uk.gov.di.ipv.core.library.config.ConfigurationVariable;
import uk.gov.di.ipv.core.library.domain.Cri;
import uk.gov.di.ipv.core.library.exceptions.ConfigParameterNotFoundException;

import java.io.File;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;

class YamlConfigServiceTest {

    private YamlConfigService getConfigService() throws Exception {
        return getConfigService(false);
    }

    private YamlConfigService getConfigService(boolean useApiConfig) throws Exception {
        var params =
                new File(YamlConfigServiceTest.class.getResource("/test-parameters.yaml").toURI());
        var secrets =
                new File(YamlConfigServiceTest.class.getResource("/test-secrets.yaml").toURI());

        return useApiConfig
                ? new YamlConfigService(
                        params,
                        secrets,
                        new File(
                                YamlConfigServiceTest.class
                                        .getResource("/test-api-config.yaml")
                                        .toURI()))
                : new YamlConfigService(params, secrets, null);
    }

    @Test
    void usesApiClientConfigWhenSpecified() throws Exception {
        var configService = getConfigService(true);

        var param = configService.getParameter(ConfigurationVariable.CLIENT_JWKS_URL, "orchStub");

        assertEquals("client-specific-jwks-url", param);
    }

    @Test
    void usesBaseParamsWhenSpecifyingNotToUseApiConfig() throws Exception {
        var configService = getConfigService(false);

        var param = configService.getParameter(ConfigurationVariable.CLIENT_JWKS_URL, "orchStub");

        assertEquals("test-jwks-url", param);
    }

    @Test
    void getParameterReturnsParameters() throws Exception {
        var configService = getConfigService();

        var param = configService.getParameter(ConfigurationVariable.COMPONENT_ID);

        assertEquals("test-component-id", param);
    }

    @Test
    void getParameterReturnsParametersWithFeatureOverride() throws Exception {
        var configService = getConfigService();
        configService.setFeatureSet(List.of("testFeature"));

        var param = configService.getParameter(ConfigurationVariable.COMPONENT_ID);

        assertEquals("alternate-component-id", param);
        configService.removeFeatureSet();
    }

    @Test
    void getParameterReturnsParametersWithoutUnrelatedFeatureOverride() throws Exception {
        var configService = getConfigService();
        configService.setFeatureSet(List.of("someOtherFeature"));

        var param = configService.getParameter(ConfigurationVariable.COMPONENT_ID);

        assertEquals("test-component-id", param);
        configService.removeFeatureSet();
    }

    @Test
    void getParameterThrowsForMissingValue() throws Exception {
        var configService = getConfigService();

        assertThrows(
                ConfigParameterNotFoundException.class,
                () -> configService.getParameter(ConfigurationVariable.EVCS_APPLICATION_URL));
    }

    @Test
    void getSecretReturnsSecret() throws Exception {
        var configService = getConfigService();

        var secret = configService.getSecret(ConfigurationVariable.GOV_UK_NOTIFY_API_KEY);

        assertEquals("test-api-key", secret);
    }

    @Test
    void getCriByIssuerReturnsCri() throws Exception {
        var configService = getConfigService();

        var cri = configService.getCriByIssuer("test-issuer");

        assertEquals(Cri.ADDRESS, cri);
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
