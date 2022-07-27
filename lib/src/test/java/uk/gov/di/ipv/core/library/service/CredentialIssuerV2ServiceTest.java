package uk.gov.di.ipv.core.library.service;

import com.github.tomakehurst.wiremock.junit5.WireMockTest;
import com.nimbusds.oauth2.sdk.http.HTTPResponse;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import uk.gov.di.ipv.core.library.domain.CredentialIssuerException;
import uk.gov.di.ipv.core.library.domain.ErrorResponse;
import uk.gov.di.ipv.core.library.persistence.DataStore;
import uk.gov.di.ipv.core.library.persistence.item.UserIssuedCredentialsV2Item;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.verify;
import static uk.gov.di.ipv.core.library.fixtures.TestFixtures.SIGNED_VC_1;

@WireMockTest
@ExtendWith(MockitoExtension.class)
class CredentialIssuerV2ServiceTest {
    private static final String TEST_USER_ID = "a-user-id";
    private static final String TEST_CRI_ID = "a-cri-id";

    @Mock private DataStore<UserIssuedCredentialsV2Item> mockDataStore;
    @Mock private ConfigurationService mockConfigurationService;

    private CredentialIssuerV2Service credentialIssuerV2Service;

    @BeforeEach
    void setUp() {
        credentialIssuerV2Service =
                new CredentialIssuerV2Service(mockDataStore, mockConfigurationService);
    }

    @Test
    void expectedSuccessWhenSaveCredentials() {
        ArgumentCaptor<UserIssuedCredentialsV2Item> userIssuedCredentialsItemCaptor =
                ArgumentCaptor.forClass(UserIssuedCredentialsV2Item.class);

        credentialIssuerV2Service.persistUserCredentials(SIGNED_VC_1, TEST_CRI_ID, TEST_USER_ID);
        verify(mockDataStore).create(userIssuedCredentialsItemCaptor.capture());
        assertEquals(TEST_USER_ID, userIssuedCredentialsItemCaptor.getValue().getUserId());
        assertEquals(TEST_CRI_ID, userIssuedCredentialsItemCaptor.getValue().getCredentialIssuer());
        assertEquals(SIGNED_VC_1, userIssuedCredentialsItemCaptor.getValue().getCredential());
    }

    @Test
    void expectedExceptionWhenSaveCredentials() {
        doThrow(new UnsupportedOperationException()).when(mockDataStore).create(any());

        CredentialIssuerException thrown =
                assertThrows(
                        CredentialIssuerException.class,
                        () ->
                                credentialIssuerV2Service.persistUserCredentials(
                                        SIGNED_VC_1, TEST_CRI_ID, TEST_USER_ID));

        assertNotNull(thrown);
        assertEquals(HTTPResponse.SC_SERVER_ERROR, thrown.getHttpStatusCode());
        assertEquals(ErrorResponse.FAILED_TO_SAVE_CREDENTIAL, thrown.getErrorResponse());
    }
}
