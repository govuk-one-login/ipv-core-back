package uk.gov.di.ipv.core.library.service;

import org.junit.jupiter.api.Test;
import uk.gov.di.ipv.core.library.config.ConfigurationVariable;
import uk.gov.di.ipv.core.library.domain.Cri;

import java.io.File;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;

public class YamlConfigServiceTest {

    private ConfigService getConfigService() throws Exception {
        return new YamlConfigService(
                new File(YamlConfigServiceTest.class.getResource("/test-parameters.yaml").toURI()),
                new File(YamlConfigServiceTest.class.getResource("/test-secrets.yaml").toURI()));
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
    }

    @Test
    void getParameterReturnsParametersWithoutUnrelatedFeatureOverride() throws Exception {
        var configService = getConfigService();
        configService.setFeatureSet(List.of("someOtherFeature"));

        var param = configService.getParameter(ConfigurationVariable.COMPONENT_ID);

        assertEquals("test-component-id", param);
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
}
