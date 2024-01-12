package uk.gov.di.ipv.core.replaycimitvcs;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import uk.gov.di.ipv.core.library.cimit.exception.CiPostMitigationsException;
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
import static org.mockito.ArgumentMatchers.anyList;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.doThrow;
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
    void shouldSubmitVcListToCimit() throws CiPostMitigationsException {
        @SuppressWarnings("unchecked")
        InputStream inputStream =
                ReplayCimitVcsHandlerTest.class.getResourceAsStream("/testReplayRequest.json");
        when(mockVerifiableCredentialService.getVcStoreItem(TEST_USER_ID, TEST_CRI_ID))
                .thenReturn(createVcStoreItem(ADDRESS_CRI, M1A_ADDRESS_VC));

        this.replayCimitVcsHandler.handleRequest(inputStream, null, null);

        ArgumentCaptor<List<String>> postedVcsCaptor = ArgumentCaptor.forClass(List.class);
        ArgumentCaptor<String> govukSigninJourneyIdCaptor = ArgumentCaptor.forClass(String.class);
        ArgumentCaptor<String> ipAddressCaptor = ArgumentCaptor.forClass(String.class);
        verify(ciMitService, times(1))
                .submitMitigatingVcList(
                        postedVcsCaptor.capture(),
                        govukSigninJourneyIdCaptor.capture(),
                        ipAddressCaptor.capture());
        var postedVcs = postedVcsCaptor.getValue();
        assertEquals(1, postedVcs.size());
        assertEquals(M1A_ADDRESS_VC, postedVcs.get(0));
        List<String> ciJourneyIds = govukSigninJourneyIdCaptor.getAllValues();
        assertEquals(1, ciJourneyIds.size());
        assertNull(ciJourneyIds.get(0));
        List<String> ciIpAddresses = ipAddressCaptor.getAllValues();
        assertEquals(1, ciIpAddresses.size());
        assertNull(ciIpAddresses.get(0));
    }

    @Test
    void shouldHandleICiPostMitigationsExceptionOnSubmitVcList() throws CiPostMitigationsException, IOException {
        try (InputStream inputStream =
                ReplayCimitVcsHandlerTest.class.getResourceAsStream("/testReplayRequest.json")) {
            when(mockVerifiableCredentialService.getVcStoreItem(TEST_USER_ID, TEST_CRI_ID))
                    .thenReturn(createVcStoreItem(ADDRESS_CRI, M1A_ADDRESS_VC));
            doThrow(new CiPostMitigationsException("Lambda execution failed"))
                    .when(ciMitService)
                    .submitMitigatingVcList(anyList(), eq(null), eq(null));

            assertThrows(
                    RuntimeException.class,
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
}
