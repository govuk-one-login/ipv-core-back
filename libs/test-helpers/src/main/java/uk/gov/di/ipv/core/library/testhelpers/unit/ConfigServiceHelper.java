package uk.gov.di.ipv.core.library.testhelpers.unit;

import uk.gov.di.ipv.core.library.config.domain.Config;
import uk.gov.di.ipv.core.library.config.domain.CredentialIssuersConfig;
import uk.gov.di.ipv.core.library.config.domain.CriConnectionWrapper;
import uk.gov.di.ipv.core.library.config.domain.InternalOperationsConfig;
import uk.gov.di.ipv.core.library.service.ConfigService;

import java.net.URI;

import static org.mockito.Mockito.*;

public final class ConfigServiceHelper {
    private ConfigServiceHelper() {}

    public static Config stubDefaultComponentIdConfig(
            ConfigService configService, Config mockConfig) {
        InternalOperationsConfig mockSelf = mock(InternalOperationsConfig.class);

        when(configService.getConfiguration()).thenReturn(mockConfig);
        when(mockConfig.getSelf()).thenReturn(mockSelf);
        when(mockSelf.getComponentId()).thenReturn(URI.create("https://core-component.example"));

        return mockConfig;
    }

    public static CriConnectionWrapper stubAllowedShareAttributes(
            Config mockConfig, String criId, String value) {
        CredentialIssuersConfig mockIssuers = mock(CredentialIssuersConfig.class);
        when(mockConfig.getCredentialIssuers()).thenReturn(mockIssuers);

        CriConnectionWrapper wrapper = mock(CriConnectionWrapper.class);
        when(mockIssuers.getById(criId)).thenReturn(wrapper);
        when(wrapper.getAllowedSharedAttributes()).thenReturn(value);

        return wrapper;
    }
}
