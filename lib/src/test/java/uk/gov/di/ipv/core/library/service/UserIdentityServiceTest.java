package uk.gov.di.ipv.core.library.service;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import uk.gov.di.ipv.core.library.persistence.DataStore;
import uk.gov.di.ipv.core.library.persistence.item.UserIssuedCredentialsItem;

import java.time.LocalDateTime;
import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
class UserIdentityServiceTest {

    @Mock private ConfigurationService mockConfigurationService;

    @Mock private DataStore<UserIssuedCredentialsItem> mockDataStore;

    private UserIdentityService userIdentityService;

    @BeforeEach
    void setUp() {
        userIdentityService = new UserIdentityService(mockConfigurationService, mockDataStore);
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

    @Test
    void shouldReturnDebugCredentialsFromDataStore() {
        List<UserIssuedCredentialsItem> userIssuedCredentialsItemList =
                List.of(
                        createUserIssuedCredentialsItem(
                                "ipv-session-id-1",
                                "PassportIssuer",
                                "{ \"gpg45Score\": { \"verification\": \"2\"} }",
                                LocalDateTime.parse("2022-01-25T12:28:56.414849")),
                        createUserIssuedCredentialsItem(
                                "ipv-session-id-1",
                                "FraudIssuer",
                                "{ \"gpg45Score\": { \"activity\": \"1\"} }",
                                LocalDateTime.parse("2022-01-25T12:28:56.414849")));

        when(mockDataStore.getItems(anyString())).thenReturn(userIssuedCredentialsItemList);

        Map<String, String> credentials =
                userIdentityService.getUserIssuedDebugCredentials("ipv-session-id-1");

        assertEquals(
                "{\"attributes\":{\"ipvSessionId\":\"ipv-session-id-1\",\"dateCreated\":\"2022-01-25T12:28:56.414849\"},\"gpg45Score\":{\"verification\":2.0}}",
                credentials.get("PassportIssuer"));
        assertEquals(
                "{\"attributes\":{\"ipvSessionId\":\"ipv-session-id-1\",\"dateCreated\":\"2022-01-25T12:28:56.414849\"},\"gpg45Score\":{\"activity\":1.0}}",
                credentials.get("FraudIssuer"));
    }

    @Test
    void shouldReturnDebugCredentialsFromDataStoreWhenMissingAGpg45Score() {
        List<UserIssuedCredentialsItem> userIssuedCredentialsItemList =
                List.of(
                        createUserIssuedCredentialsItem(
                                "ipv-session-id-1",
                                "PassportIssuer",
                                "{ \"test\": \"test-value\"}",
                                LocalDateTime.parse("2022-01-25T12:28:56.414849")),
                        createUserIssuedCredentialsItem(
                                "ipv-session-id-1",
                                "FraudIssuer",
                                "{ \"test\": \"test-value\"}",
                                LocalDateTime.parse("2022-01-25T12:28:56.414849")));

        when(mockDataStore.getItems(anyString())).thenReturn(userIssuedCredentialsItemList);

        Map<String, String> credentials =
                userIdentityService.getUserIssuedDebugCredentials("ipv-session-id-1");

        assertEquals(
                "{\"attributes\":{\"ipvSessionId\":\"ipv-session-id-1\",\"dateCreated\":\"2022-01-25T12:28:56.414849\"}}",
                credentials.get("PassportIssuer"));
        assertEquals(
                "{\"attributes\":{\"ipvSessionId\":\"ipv-session-id-1\",\"dateCreated\":\"2022-01-25T12:28:56.414849\"}}",
                credentials.get("FraudIssuer"));
    }

    @Test
    void shouldReturnDebugCredentialsEvenIfFailingToParseCredentialJson() {
        List<UserIssuedCredentialsItem> userIssuedCredentialsItemList =
                List.of(
                        createUserIssuedCredentialsItem(
                                "ipv-session-id-1",
                                "PassportIssuer",
                                "invalid-json",
                                LocalDateTime.parse("2022-01-25T12:28:56.414849")));

        when(mockDataStore.getItems(anyString())).thenReturn(userIssuedCredentialsItemList);

        Map<String, String> credentials =
                userIdentityService.getUserIssuedDebugCredentials("ipv-session-id-1");

        assertEquals(
                "{\"attributes\":{\"ipvSessionId\":\"ipv-session-id-1\",\"dateCreated\":\"2022-01-25T12:28:56.414849\"}}",
                credentials.get("PassportIssuer"));
    }

    @Test
    void shouldReturnDebugCredentialsEvenIfFailingToParseGpg45ScoreParamFromJson() {
        List<UserIssuedCredentialsItem> userIssuedCredentialsItemList =
                List.of(
                        createUserIssuedCredentialsItem(
                                "ipv-session-id-1",
                                "PassportIssuer",
                                "{ \"gpg45Score\": \"invalid gpg45 json\" }",
                                LocalDateTime.parse("2022-01-25T12:28:56.414849")));

        when(mockDataStore.getItems(anyString())).thenReturn(userIssuedCredentialsItemList);

        Map<String, String> credentials =
                userIdentityService.getUserIssuedDebugCredentials("ipv-session-id-1");

        assertEquals(
                "{\"attributes\":{\"ipvSessionId\":\"ipv-session-id-1\",\"dateCreated\":\"2022-01-25T12:28:56.414849\"}}",
                credentials.get("PassportIssuer"));
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
