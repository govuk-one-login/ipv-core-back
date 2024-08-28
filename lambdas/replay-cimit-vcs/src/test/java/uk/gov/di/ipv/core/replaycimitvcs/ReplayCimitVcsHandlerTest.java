package uk.gov.di.ipv.core.replaycimitvcs;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import uk.gov.di.ipv.core.library.cimit.exception.CiPostMitigationsException;
import uk.gov.di.ipv.core.library.cimit.exception.CiPutException;
import uk.gov.di.ipv.core.library.domain.VerifiableCredential;
import uk.gov.di.ipv.core.library.exceptions.CredentialParseException;
import uk.gov.di.ipv.core.library.exceptions.FailedVcReplayException;
import uk.gov.di.ipv.core.library.service.CimitService;
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
import static uk.gov.di.ipv.core.library.fixtures.VcFixtures.M1A_ADDRESS_VC;

@ExtendWith(MockitoExtension.class)
class ReplayCimitVcsHandlerTest {
    private static final String TEST_USER_ID = "test-user-id";
    private static final String TEST_CRI_ID = "address";

    @Mock private CimitService cimitService;
    @Mock private ConfigService configService;
    @Mock private VerifiableCredentialService mockVerifiableCredentialService;
    @InjectMocks private ReplayCimitVcsHandler replayCimitVcsHandler;

    @Test
    void shouldSubmitVcsToCimit() throws Exception {
        InputStream inputStream =
                ReplayCimitVcsHandlerTest.class.getResourceAsStream("/testReplayRequest.json");
        when(mockVerifiableCredentialService.getVc(TEST_USER_ID, TEST_CRI_ID))
                .thenReturn(M1A_ADDRESS_VC);

        this.replayCimitVcsHandler.handleRequest(inputStream, null, null);

        var postedVcCaptor = ArgumentCaptor.forClass(VerifiableCredential.class);
        ArgumentCaptor<String> govukSigninJourneyIdCaptor = ArgumentCaptor.forClass(String.class);
        ArgumentCaptor<String> ipAddressCaptor = ArgumentCaptor.forClass(String.class);
        verify(cimitService, times(1))
                .submitVC(
                        postedVcCaptor.capture(),
                        govukSigninJourneyIdCaptor.capture(),
                        ipAddressCaptor.capture());
        var postedVc = postedVcCaptor.getValue();
        assertEquals(M1A_ADDRESS_VC, postedVc);
        List<String> ciJourneyIds = govukSigninJourneyIdCaptor.getAllValues();
        assertEquals(1, ciJourneyIds.size());
        assertNull(ciJourneyIds.get(0));
        List<String> ciIpAddresses = ipAddressCaptor.getAllValues();
        assertEquals(1, ciIpAddresses.size());
        assertNull(ciIpAddresses.get(0));
    }

    @Test
    void shouldNotAttemptSubmitOnNullVc() throws CiPutException, CredentialParseException {
        InputStream inputStream =
                ReplayCimitVcsHandlerTest.class.getResourceAsStream("/testReplayRequest.json");
        when(mockVerifiableCredentialService.getVc(TEST_USER_ID, TEST_CRI_ID)).thenReturn(null);

        this.replayCimitVcsHandler.handleRequest(inputStream, null, null);

        verify(cimitService, never()).submitVC(any(), any(), any());
    }

    @Test
    void shouldHandleICiPutExceptionOnSubmitVcList()
            throws IOException, CiPutException, CredentialParseException {
        try (InputStream inputStream =
                ReplayCimitVcsHandlerTest.class.getResourceAsStream("/testReplayRequest.json")) {
            when(mockVerifiableCredentialService.getVc(TEST_USER_ID, TEST_CRI_ID))
                    .thenReturn(M1A_ADDRESS_VC);
            doThrow(new CiPutException("Lambda execution failed"))
                    .when(cimitService)
                    .submitVC(any(), eq(null), eq(null));

            assertThrows(
                    FailedVcReplayException.class,
                    () -> this.replayCimitVcsHandler.handleRequest(inputStream, null, null));
        }
    }

    @Test
    void shouldHandleICiPostMitigationsExceptionOnSubmitVcList()
            throws IOException, CiPostMitigationsException, CredentialParseException {
        try (InputStream inputStream =
                ReplayCimitVcsHandlerTest.class.getResourceAsStream("/testReplayRequest.json")) {
            when(mockVerifiableCredentialService.getVc(TEST_USER_ID, TEST_CRI_ID))
                    .thenReturn(M1A_ADDRESS_VC);
            doThrow(new CiPostMitigationsException("Lambda execution failed"))
                    .when(cimitService)
                    .submitMitigatingVcList(anyList(), eq(null), eq(null));

            assertThrows(
                    FailedVcReplayException.class,
                    () -> this.replayCimitVcsHandler.handleRequest(inputStream, null, null));
        }
    }
}
