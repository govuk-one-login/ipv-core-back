package uk.gov.di.ipv.service;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import uk.gov.di.ipv.persistence.DataStore;
import uk.gov.di.ipv.persistence.item.UserIssuedCredentialsItem;
import uk.org.webcompere.systemstubs.environment.EnvironmentVariables;
import uk.org.webcompere.systemstubs.jupiter.SystemStub;
import uk.org.webcompere.systemstubs.jupiter.SystemStubsExtension;
import uk.org.webcompere.systemstubs.properties.SystemProperties;

import java.time.LocalDateTime;
import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.when;
import static uk.gov.di.ipv.service.ConfigurationService.IS_LOCAL;

@ExtendWith(SystemStubsExtension.class)
@ExtendWith(MockitoExtension.class)
class UserIdentityServiceTest {

    @SystemStub private EnvironmentVariables environmentVariables;

    @SystemStub private SystemProperties systemProperties;

    @Mock private ConfigurationService mockConfigurationService;

    @Mock private DataStore<UserIssuedCredentialsItem> mockDataStore;

    private UserIdentityService userIdentityService;

    @BeforeEach
    void setUp() {
        userIdentityService = new UserIdentityService(mockConfigurationService, mockDataStore);
    }

    @Test
    void noArgsConstructor() {
        environmentVariables.set(IS_LOCAL, "true");
        systemProperties.set(
                "software.amazon.awssdk.http.service.impl",
                "software.amazon.awssdk.http.urlconnection.UrlConnectionSdkHttpService");

        assertDoesNotThrow(() -> new UserIdentityService());
    }

    @Test
    void shouldReturnCredentialsFromDataStore() {
        List<UserIssuedCredentialsItem> userIssuedCredentialsItemList =
                List.of(
                        createUserIssuedCredentialsItem(
                                "ipv-session-id-1",
                                "PassportIssuer",
                                "Test credential 1",
                                LocalDateTime.now()),
                        createUserIssuedCredentialsItem(
                                "ipv-session-id-1",
                                "FraudIssuer",
                                "Test credential 2",
                                LocalDateTime.now()));

        when(mockDataStore.getItems(anyString())).thenReturn(userIssuedCredentialsItemList);

        Map<String, String> credentials =
                userIdentityService.getUserIssuedCredentials("ipv-session-id-1");

        assertEquals("Test credential 1", credentials.get("PassportIssuer"));
        assertEquals("Test credential 2", credentials.get("FraudIssuer"));
    }

    private UserIssuedCredentialsItem createUserIssuedCredentialsItem(
            String ipvSessionId,
            String credentialIssuer,
            String credential,
            LocalDateTime dateCreated) {
        UserIssuedCredentialsItem userIssuedCredentialsItem = new UserIssuedCredentialsItem();
        userIssuedCredentialsItem.setIpvSessionId(ipvSessionId);
        userIssuedCredentialsItem.setCredentialIssuer(credentialIssuer);
        userIssuedCredentialsItem.setCredential(credential);
        userIssuedCredentialsItem.setDateCreated(dateCreated);
        return userIssuedCredentialsItem;
    }
}
