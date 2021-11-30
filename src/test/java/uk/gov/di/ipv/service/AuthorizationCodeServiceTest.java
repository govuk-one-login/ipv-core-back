package uk.gov.di.ipv.service;

import com.nimbusds.oauth2.sdk.AuthorizationCode;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import uk.gov.di.ipv.persistence.DataStore;
import uk.gov.di.ipv.persistence.item.AuthorizationCodeItem;

import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

public class AuthorizationCodeServiceTest {

    private final DataStore<AuthorizationCodeItem> mockDataStore = mock(DataStore.class);
    private final ConfigurationService mockConfigurationService = mock(ConfigurationService.class);

    private AuthorizationCodeService authorizationCodeService;

    @BeforeEach
    public void setUp() {
        when(mockConfigurationService.getAuthCodesTableName()).thenReturn("test-auth-code-table");

        authorizationCodeService = new AuthorizationCodeService(mockDataStore, mockConfigurationService);
    }

    @Test
    public void shouldReturnAnAuthorisationCode() {
        AuthorizationCode result = authorizationCodeService.generateAuthorizationCode();

        assertNotNull(result);
    }


    @Test
    public void shouldCreateAuthorizationCodeInDataStore() {
        AuthorizationCode testCode = new AuthorizationCode();
        authorizationCodeService.persistAuthorizationCode(testCode.getValue(), "session-12345");

        verify(mockDataStore).create(any(AuthorizationCodeItem.class));
    }
}
