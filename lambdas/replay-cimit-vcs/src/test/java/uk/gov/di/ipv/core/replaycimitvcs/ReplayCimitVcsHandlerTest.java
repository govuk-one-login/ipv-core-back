package uk.gov.di.ipv.core.replaycimitvcs;

import com.nimbusds.jwt.SignedJWT;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import uk.gov.di.ipv.core.library.cimit.exception.CiPostMitigationsException;
import uk.gov.di.ipv.core.library.cimit.exception.CiPutException;
import uk.gov.di.ipv.core.library.exceptions.FailedVcReplayException;
import uk.gov.di.ipv.core.library.persistence.item.VcStoreItem;
import uk.gov.di.ipv.core.library.service.CiMitService;
import uk.gov.di.ipv.core.library.service.ConfigService;
import uk.gov.di.ipv.core.library.verifiablecredential.service.VerifiableCredentialService;

import java.io.IOException;
import java.io.InputStream;
import java.time.Instant;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyList;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;
import static uk.gov.di.ipv.core.library.domain.CriConstants.ADDRESS_CRI;
import static uk.gov.di.ipv.core.library.fixtures.TestFixtures.M1A_ADDRESS_VC;

@ExtendWith(MockitoExtension.class)
class ReplayCimitVcsHandlerTest {
    private static final String TEST_USER_ID = "test-user-id";
    private static final String TEST_CRI_ID = "address";
    @Mock private CiMitService ciMitService;
    @Mock private ConfigService configService;
    @Mock private VerifiableCredentialService mockVerifiableCredentialService;
    @InjectMocks private ReplayCimitVcsHandler replayCimitVcsHandler;

    @Test
    void shouldSubmitVcsToCimit() throws CiPutException {
        InputStream inputStream =
                ReplayCimitVcsHandlerTest.class.getResourceAsStream("/testReplayRequest.json");
        when(mockVerifiableCredentialService.getVcStoreItem(TEST_USER_ID, TEST_CRI_ID))
                .thenReturn(createVcStoreItem(ADDRESS_CRI, M1A_ADDRESS_VC));

        this.replayCimitVcsHandler.handleRequest(inputStream, null, null);

        ArgumentCaptor<SignedJWT> postedVcCaptor = ArgumentCaptor.forClass(SignedJWT.class);
        ArgumentCaptor<String> govukSigninJourneyIdCaptor = ArgumentCaptor.forClass(String.class);
        ArgumentCaptor<String> ipAddressCaptor = ArgumentCaptor.forClass(String.class);
        verify(ciMitService, times(1))
                .submitVC(
                        postedVcCaptor.capture(),
                        govukSigninJourneyIdCaptor.capture(),
                        ipAddressCaptor.capture());
        var postedVc = postedVcCaptor.getValue();
        assertEquals(M1A_ADDRESS_VC, postedVc.serialize());
        List<String> ciJourneyIds = govukSigninJourneyIdCaptor.getAllValues();
        assertEquals(1, ciJourneyIds.size());
        assertNull(ciJourneyIds.get(0));
        List<String> ciIpAddresses = ipAddressCaptor.getAllValues();
        assertEquals(1, ciIpAddresses.size());
        assertNull(ciIpAddresses.get(0));
    }

    @Test
    void shouldNotAttemptSubmitOnNullCredential() throws CiPutException {
        InputStream inputStream =
                ReplayCimitVcsHandlerTest.class.getResourceAsStream("/testReplayRequest.json");
        when(mockVerifiableCredentialService.getVcStoreItem(TEST_USER_ID, TEST_CRI_ID))
                .thenReturn(createNullCredentialVcStoreItem());

        this.replayCimitVcsHandler.handleRequest(inputStream, null, null);

        verify(ciMitService, never()).submitVC(any(), any(), any());
    }

    @Test
    void shouldHandleParseException() throws IOException {
        try (InputStream inputStream =
                ReplayCimitVcsHandlerTest.class.getResourceAsStream("/testReplayRequest.json")) {
            when(mockVerifiableCredentialService.getVcStoreItem(TEST_USER_ID, TEST_CRI_ID))
                    .thenReturn(createInvalidVcStoreItem());
            assertThrows(
                    FailedVcReplayException.class,
                    () -> this.replayCimitVcsHandler.handleRequest(inputStream, null, null));
        }
    }

    @Test
    void shouldHandleICiPutExceptionOnSubmitVcList() throws IOException, CiPutException {
        try (InputStream inputStream =
                ReplayCimitVcsHandlerTest.class.getResourceAsStream("/testReplayRequest.json")) {
            when(mockVerifiableCredentialService.getVcStoreItem(TEST_USER_ID, TEST_CRI_ID))
                    .thenReturn(createVcStoreItem(ADDRESS_CRI, M1A_ADDRESS_VC));
            doThrow(new CiPutException("Lambda execution failed"))
                    .when(ciMitService)
                    .submitVC(any(), eq(null), eq(null));

            assertThrows(
                    FailedVcReplayException.class,
                    () -> this.replayCimitVcsHandler.handleRequest(inputStream, null, null));
        }
    }

    @Test
    void shouldHandleICiPostMitigationsExceptionOnSubmitVcList()
            throws IOException, CiPostMitigationsException {
        try (InputStream inputStream =
                ReplayCimitVcsHandlerTest.class.getResourceAsStream("/testReplayRequest.json")) {
            when(mockVerifiableCredentialService.getVcStoreItem(TEST_USER_ID, TEST_CRI_ID))
                    .thenReturn(createVcStoreItem(ADDRESS_CRI, M1A_ADDRESS_VC));
            doThrow(new CiPostMitigationsException("Lambda execution failed"))
                    .when(ciMitService)
                    .submitMitigatingVcList(anyList(), eq(null), eq(null));

            assertThrows(
                    FailedVcReplayException.class,
                    () -> this.replayCimitVcsHandler.handleRequest(inputStream, null, null));
        }
    }

    private VcStoreItem createVcStoreItem(String credentialIssuer, String credential) {
        Instant dateCreated = Instant.now();
        VcStoreItem vcStoreItem = new VcStoreItem();
        vcStoreItem.setUserId(TEST_USER_ID);
        vcStoreItem.setCredentialIssuer(credentialIssuer);
        vcStoreItem.setCredential(credential);
        vcStoreItem.setDateCreated(dateCreated);
        vcStoreItem.setExpirationTime(dateCreated.plusSeconds(1000L));
        return vcStoreItem;
    }

    private VcStoreItem createInvalidVcStoreItem() {
        Instant dateCreated = Instant.now();
        VcStoreItem vcStoreItem = new VcStoreItem();
        vcStoreItem.setUserId(TEST_USER_ID);
        vcStoreItem.setCredential("invalid-credential");
        vcStoreItem.setDateCreated(dateCreated);
        vcStoreItem.setExpirationTime(dateCreated.plusSeconds(1000L));
        return vcStoreItem;
    }

    private VcStoreItem createNullCredentialVcStoreItem() {
        Instant dateCreated = Instant.now();
        VcStoreItem vcStoreItem = new VcStoreItem();
        vcStoreItem.setUserId(TEST_USER_ID);
        vcStoreItem.setDateCreated(dateCreated);
        vcStoreItem.setExpirationTime(dateCreated.plusSeconds(1000L));
        return vcStoreItem;
    }
}
