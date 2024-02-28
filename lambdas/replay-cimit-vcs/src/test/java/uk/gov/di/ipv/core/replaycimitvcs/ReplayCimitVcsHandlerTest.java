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
import uk.gov.di.ipv.core.library.fixtures.TestFixtures;
import uk.gov.di.ipv.core.library.service.CiMitService;
import uk.gov.di.ipv.core.library.service.ConfigService;
import uk.gov.di.ipv.core.library.verifiablecredential.service.VerifiableCredentialService;

import java.io.IOException;
import java.io.InputStream;
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
import static uk.gov.di.ipv.core.library.fixtures.VcFixtures.vcAddressM1a;

@ExtendWith(MockitoExtension.class)
class ReplayCimitVcsHandlerTest {
    private static final String TEST_USER_ID = "test-user-id";
    private static final String TEST_CRI_ID = "address";

    @Mock private CiMitService ciMitService;
    @Mock private ConfigService configService;
    @Mock private VerifiableCredentialService mockVerifiableCredentialService;
    @InjectMocks private ReplayCimitVcsHandler replayCimitVcsHandler;

    @Test
    void shouldSubmitVcsToCimit() throws Exception {
        String addressVc = vcAddressM1a();
        InputStream inputStream =
                ReplayCimitVcsHandlerTest.class.getResourceAsStream("/testReplayRequest.json");
        when(mockVerifiableCredentialService.getVcStoreItem(TEST_USER_ID, TEST_CRI_ID))
                .thenReturn(
                        TestFixtures.createVcStoreItem(TEST_USER_ID, ADDRESS_CRI, addressVc));

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
        assertEquals(addressVc, postedVc.serialize());
        List<String> ciJourneyIds = govukSigninJourneyIdCaptor.getAllValues();
        assertEquals(1, ciJourneyIds.size());
        assertNull(ciJourneyIds.get(0));
        List<String> ciIpAddresses = ipAddressCaptor.getAllValues();
        assertEquals(1, ciIpAddresses.size());
        assertNull(ciIpAddresses.get(0));
    }

    @Test
    void shouldNotAttemptSubmitOnNullVc() throws CiPutException {
        InputStream inputStream =
                ReplayCimitVcsHandlerTest.class.getResourceAsStream("/testReplayRequest.json");
        when(mockVerifiableCredentialService.getVcStoreItem(TEST_USER_ID, TEST_CRI_ID))
                .thenReturn(null);

        this.replayCimitVcsHandler.handleRequest(inputStream, null, null);

        verify(ciMitService, never()).submitVC(any(), any(), any());
    }

    @Test
    void shouldHandleParseException() throws IOException {
        try (InputStream inputStream =
                ReplayCimitVcsHandlerTest.class.getResourceAsStream("/testReplayRequest.json")) {
            when(mockVerifiableCredentialService.getVcStoreItem(TEST_USER_ID, TEST_CRI_ID))
                    .thenReturn(
                            TestFixtures.createInvalidVcStoreItem(
                                    TEST_USER_ID, ADDRESS_CRI, "invalid-credential"));
            assertThrows(
                    FailedVcReplayException.class,
                    () -> this.replayCimitVcsHandler.handleRequest(inputStream, null, null));
        }
    }

    @Test
    void shouldHandleICiPutExceptionOnSubmitVcList() throws Exception {
        try (InputStream inputStream =
                ReplayCimitVcsHandlerTest.class.getResourceAsStream("/testReplayRequest.json")) {
            when(mockVerifiableCredentialService.getVcStoreItem(TEST_USER_ID, TEST_CRI_ID))
                    .thenReturn(
                            TestFixtures.createVcStoreItem(
                                    TEST_USER_ID, ADDRESS_CRI, vcAddressM1a()));
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
            throws Exception {
        try (InputStream inputStream =
                ReplayCimitVcsHandlerTest.class.getResourceAsStream("/testReplayRequest.json")) {
            when(mockVerifiableCredentialService.getVcStoreItem(TEST_USER_ID, TEST_CRI_ID))
                    .thenReturn(
                            TestFixtures.createVcStoreItem(
                                    TEST_USER_ID, ADDRESS_CRI, vcAddressM1a()));
            doThrow(new CiPostMitigationsException("Lambda execution failed"))
                    .when(ciMitService)
                    .submitMitigatingVcList(anyList(), eq(null), eq(null));

            assertThrows(
                    FailedVcReplayException.class,
                    () -> this.replayCimitVcsHandler.handleRequest(inputStream, null, null));
        }
    }
}
