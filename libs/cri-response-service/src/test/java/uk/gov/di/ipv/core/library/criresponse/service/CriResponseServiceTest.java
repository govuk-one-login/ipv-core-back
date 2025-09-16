package uk.gov.di.ipv.core.library.criresponse.service;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import org.mockito.ArgumentCaptor;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import uk.gov.di.ipv.core.library.config.domain.Config;
import uk.gov.di.ipv.core.library.config.domain.InternalOperationsConfig;
import uk.gov.di.ipv.core.library.domain.VerifiableCredential;
import uk.gov.di.ipv.core.library.persistence.DataStore;
import uk.gov.di.ipv.core.library.persistence.item.ClientOAuthSessionItem;
import uk.gov.di.ipv.core.library.persistence.item.CriResponseItem;
import uk.gov.di.ipv.core.library.service.ConfigService;

import java.time.Instant;
import java.util.ArrayList;
import java.util.List;
import java.util.Objects;
import java.util.UUID;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.anyLong;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;
import static uk.gov.di.ipv.core.library.domain.Cri.ADDRESS;
import static uk.gov.di.ipv.core.library.domain.Cri.DCMAW_ASYNC;
import static uk.gov.di.ipv.core.library.domain.Cri.F2F;
import static uk.gov.di.ipv.core.library.fixtures.VcFixtures.vcAddressTwo;
import static uk.gov.di.ipv.core.library.fixtures.VcFixtures.vcDcmawAsyncDrivingPermitDva;
import static uk.gov.di.ipv.core.library.fixtures.VcFixtures.vcF2fIdCard;
import static uk.gov.di.ipv.core.library.fixtures.VcFixtures.vcWebPassportSuccessful;

@ExtendWith(MockitoExtension.class)
class CriResponseServiceTest {
    private static final String TEST_FEATURE_SET = "test-feature-set";
    @Mock private DataStore<CriResponseItem> mockDataStore;
    @Mock private ConfigService mockConfigService;
    @Mock private Config mockConfig;
    @Mock private InternalOperationsConfig mockSelf;

    private CriResponseService criResponseService;

    private static final String USER_ID_1 = "user-id-1";
    private static final String TEST_USER_ID = UUID.randomUUID().toString();
    private static final String TEST_ISSUER_RESPONSE =
            "{\"sub\":"
                    + TEST_USER_ID
                    + "\","
                    + "\"https://vocab.account.gov.uk/v1/credentialStatus\":\"pending\"}";

    private static final String TEST_OAUTH_STATE = UUID.randomUUID().toString();

    @BeforeEach
    void setUp() {
        criResponseService = new CriResponseService(mockDataStore, mockConfigService);
    }

    private void stubDcmawPendingTtl(int ttlSeconds) {
        when(mockConfigService.getConfiguration()).thenReturn(mockConfig);
        when(mockConfig.getSelf()).thenReturn(mockSelf);
        when(mockSelf.getDcmawAsyncVcPendingReturnTtl()).thenReturn(ttlSeconds);
    }

    @Test
    void shouldReturnCredentialFromDataStoreForSpecificCri() {
        String ipvSessionId = "ipvSessionId";
        CriResponseItem criResponseItem =
                createCriResponseStoreItem(vcWebPassportSuccessful(), Instant.now());

        when(mockDataStore.getItem(ipvSessionId, ADDRESS.getId())).thenReturn(criResponseItem);

        CriResponseItem retrievedCredentialItem =
                criResponseService.getCriResponseItem(ipvSessionId, ADDRESS);

        assertEquals(criResponseItem, retrievedCredentialItem);
    }

    @Test
    void shouldPersistCriResponse() {
        var featureSet = List.of(TEST_FEATURE_SET);
        criResponseService.persistCriResponse(
                ClientOAuthSessionItem.builder()
                        .userId(TEST_USER_ID)
                        .reproveIdentity(Boolean.FALSE)
                        .build(),
                F2F,
                TEST_ISSUER_RESPONSE,
                TEST_OAUTH_STATE,
                CriResponseService.STATUS_PENDING,
                featureSet);

        ArgumentCaptor<CriResponseItem> persistedCriResponseItemCaptor =
                ArgumentCaptor.forClass(CriResponseItem.class);
        verify(mockDataStore, times(1)).create(persistedCriResponseItemCaptor.capture(), anyLong());
        assertEquals(1, persistedCriResponseItemCaptor.getAllValues().size());
        final CriResponseItem persistedCriResponseItem =
                persistedCriResponseItemCaptor.getAllValues().get(0);
        assertEquals(TEST_USER_ID, persistedCriResponseItem.getUserId());
        assertEquals(F2F.getId(), persistedCriResponseItem.getCredentialIssuer());
        assertEquals(TEST_ISSUER_RESPONSE, persistedCriResponseItem.getIssuerResponse());
        assertEquals(TEST_OAUTH_STATE, persistedCriResponseItem.getOauthState());
        assertEquals(featureSet, persistedCriResponseItem.getFeatureSet());
    }

    @Test
    void shouldReturnTrueWhenUserHasFaceToFaceRequest() {
        CriResponseItem criResponseItem =
                createCriResponseStoreItem(vcWebPassportSuccessful(), Instant.now());

        when(mockDataStore.getItem(USER_ID_1, F2F.getId())).thenReturn(criResponseItem);

        CriResponseItem retrievedCredentialItem =
                criResponseService.getCriResponseItem(USER_ID_1, F2F);

        assertFalse(Objects.isNull(retrievedCredentialItem));
    }

    @Test
    void shouldDeleteExistingWhenUserHasDeleteRequest() {
        CriResponseItem criResponseItem =
                createCriResponseStoreItem(vcWebPassportSuccessful(), Instant.now());

        when(mockDataStore.delete(USER_ID_1, F2F.getId())).thenReturn(criResponseItem);

        criResponseService.deleteCriResponseItem(USER_ID_1, F2F);

        verify(mockDataStore, times(1)).delete(USER_ID_1, F2F.getId());
    }

    @Test
    void shouldUpdateExistingWhenUserHasUpdateRequest() {
        CriResponseItem criResponseItem =
                createCriResponseStoreItem(vcWebPassportSuccessful(), Instant.now());
        when(mockDataStore.update(criResponseItem)).thenReturn(criResponseItem);

        criResponseService.updateCriResponseItem(criResponseItem);
        verify(mockDataStore, times(1)).update(criResponseItem);
    }

    @Test
    void getCriResponseItemWithStateShouldGetCorrectItem() {
        // Arrange
        var criResponseItem1 = createCriResponseStoreItem(vcWebPassportSuccessful(), Instant.now());
        var criResponseItem2 = createCriResponseStoreItem(vcWebPassportSuccessful(), Instant.now());
        criResponseItem2.setOauthState(TEST_OAUTH_STATE);
        when(mockDataStore.getItems(USER_ID_1))
                .thenReturn(List.of(criResponseItem1, criResponseItem2));

        // Act
        var criResponseItem =
                criResponseService.getCriResponseItemWithState(USER_ID_1, TEST_OAUTH_STATE);

        // Assert
        assertTrue(criResponseItem.isPresent());
        assertEquals(criResponseItem2, criResponseItem.get());
    }

    @Test
    void getCriResponseItemsShouldGetCorrectItems() {
        // Arrange
        var expectedCriResponseItems =
                List.of(
                        createCriResponseStoreItem(vcWebPassportSuccessful(), Instant.now()),
                        createCriResponseStoreItem(vcWebPassportSuccessful(), Instant.now()));
        when(mockDataStore.getItems(USER_ID_1)).thenReturn(expectedCriResponseItems);

        // Act
        var criResponseItems = criResponseService.getCriResponseItems(USER_ID_1);

        // Assert
        assertEquals(expectedCriResponseItems, criResponseItems);
    }

    @Test
    void getCriResponseItemsShouldDefaultToEmptyList() {
        // Arrange
        when(mockDataStore.getItems(USER_ID_1)).thenReturn(null);

        // Act
        var criResponseItems = criResponseService.getCriResponseItems(USER_ID_1);

        // Assert
        assertEquals(List.of(), criResponseItems);
    }

    @ParameterizedTest
    @ValueSource(booleans = {true, false})
    void getF2FAsyncResponseStatusShouldGetStatus(boolean hasVc) {
        // Arrange
        var criResponseItem = createCriResponseStoreItem(vcF2fIdCard(), Instant.now());
        when(mockDataStore.getItem(USER_ID_1, F2F.getId())).thenReturn(criResponseItem);
        var vcs =
                hasVc
                        ? List.of(vcF2fIdCard(), vcAddressTwo())
                        : new ArrayList<VerifiableCredential>();

        // Act
        var asyncCriStatus = criResponseService.getAsyncResponseStatus(USER_ID_1, vcs, false);

        // Assert
        assertEquals(F2F, asyncCriStatus.cri());
        assertEquals(CriResponseService.STATUS_PENDING, asyncCriStatus.incompleteStatus());
        assertEquals(!hasVc, asyncCriStatus.isAwaitingVc());
    }

    @Test
    void getDcmawAsyncResponseStatusShouldReturnEmptyWhenNoVc() {
        // Arrange
        var vcs = new ArrayList<VerifiableCredential>();

        // Act
        var asyncCriStatus = criResponseService.getAsyncResponseStatus(USER_ID_1, vcs, false);

        // Assert
        assertNull(asyncCriStatus.cri());
        assertNull(asyncCriStatus.incompleteStatus());
        assertFalse(asyncCriStatus.isAwaitingVc());
    }

    @Test
    void getDcmawAsyncResponseStatusShouldGetCorrectStatusForExistingDcmawAsyncVc() {
        stubDcmawPendingTtl(1000000000);
        when(criResponseService.getCriResponseItem(USER_ID_1, DCMAW_ASYNC))
                .thenReturn(new CriResponseItem());
        var vcs = List.of(vcDcmawAsyncDrivingPermitDva(), vcAddressTwo());

        var asyncCriStatus = criResponseService.getAsyncResponseStatus(USER_ID_1, vcs, false);

        assertEquals(DCMAW_ASYNC, asyncCriStatus.cri());
        assertNull(asyncCriStatus.incompleteStatus());
        assertFalse(asyncCriStatus.isAwaitingVc());
    }

    @Test
    void getAsyncResponseStatusShouldReturnEmptyWhenDcmawAsyncVcExpired() {
        // Arrange
        stubDcmawPendingTtl(-1);

        // Act
        var asyncCriStatus =
                criResponseService.getAsyncResponseStatus(
                        USER_ID_1, List.of(vcDcmawAsyncDrivingPermitDva(), vcAddressTwo()), false);

        // Assert
        assertNull(asyncCriStatus.cri());
        assertNull(asyncCriStatus.incompleteStatus());
        assertFalse(asyncCriStatus.isAwaitingVc());
    }

    @Test
    void getAsyncResponseStatusShouldReturnEmptyStatusIfNoCriResponseFound() {
        // Act
        var asyncCriStatus = criResponseService.getAsyncResponseStatus(USER_ID_1, List.of(), false);

        // Assert
        assertNull(asyncCriStatus.cri());
        assertNull(asyncCriStatus.incompleteStatus());
        assertFalse(asyncCriStatus.isAwaitingVc());
    }

    private CriResponseItem createCriResponseStoreItem(
            VerifiableCredential vc, Instant dateCreated) {
        CriResponseItem criResponseItem = new CriResponseItem();
        criResponseItem.setUserId(vc.getUserId());
        criResponseItem.setCredentialIssuer(vc.getCri().getId());
        criResponseItem.setIssuerResponse(vc.getVcString());
        criResponseItem.setDateCreated(dateCreated);
        criResponseItem.setStatus(CriResponseService.STATUS_PENDING);
        return criResponseItem;
    }
}
