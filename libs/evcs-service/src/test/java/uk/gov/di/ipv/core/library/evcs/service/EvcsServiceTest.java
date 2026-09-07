package uk.gov.di.ipv.core.library.evcs.service;

import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.Captor;
import org.mockito.InOrder;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import uk.gov.di.ipv.core.library.domain.Cri;
import uk.gov.di.ipv.core.library.domain.VerifiableCredential;
import uk.gov.di.ipv.core.library.enums.Vot;
import uk.gov.di.ipv.core.library.evcs.client.EvcsClient;
import uk.gov.di.ipv.core.library.evcs.dto.EvcsCreateUserVCsDto;
import uk.gov.di.ipv.core.library.evcs.dto.EvcsCreateUserVCsRequestBody;
import uk.gov.di.ipv.core.library.evcs.dto.EvcsGetUserVCDto;
import uk.gov.di.ipv.core.library.evcs.dto.EvcsGetUserVCsDto;
import uk.gov.di.ipv.core.library.evcs.dto.EvcsPostIdentityDto;
import uk.gov.di.ipv.core.library.evcs.dto.EvcsStoredIdentityDto;
import uk.gov.di.ipv.core.library.evcs.dto.EvcsUpdateUserVCsRequestBody;
import uk.gov.di.ipv.core.library.evcs.enums.EvcsVCState;
import uk.gov.di.ipv.core.library.evcs.exception.EvcsServiceException;
import uk.gov.di.ipv.core.library.evcs.exception.FailedToCreateStoredIdentityForEvcsException;
import uk.gov.di.ipv.core.library.exceptions.CredentialParseException;
import uk.gov.di.ipv.core.library.service.ConfigService;
import uk.gov.di.ipv.core.library.useridentity.service.VotMatchingResult;

import java.util.List;
import java.util.Map;
import java.util.Optional;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.inOrder;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;
import static uk.gov.di.ipv.core.library.enums.Vot.P0;
import static uk.gov.di.ipv.core.library.enums.Vot.P1;
import static uk.gov.di.ipv.core.library.enums.Vot.P2;
import static uk.gov.di.ipv.core.library.enums.Vot.P3;
import static uk.gov.di.ipv.core.library.evcs.enums.EvcsVCState.ABANDONED;
import static uk.gov.di.ipv.core.library.evcs.enums.EvcsVCState.CURRENT;
import static uk.gov.di.ipv.core.library.evcs.enums.EvcsVCState.HISTORIC;
import static uk.gov.di.ipv.core.library.evcs.enums.EvcsVCState.PENDING_RETURN;
import static uk.gov.di.ipv.core.library.evcs.enums.EvcsVcProvenance.OFFLINE;
import static uk.gov.di.ipv.core.library.evcs.enums.EvcsVcProvenance.ONLINE;
import static uk.gov.di.ipv.core.library.fixtures.VcFixtures.vcAddressM1a;
import static uk.gov.di.ipv.core.library.fixtures.VcFixtures.vcAddressOne;
import static uk.gov.di.ipv.core.library.fixtures.VcFixtures.vcAddressTwo;
import static uk.gov.di.ipv.core.library.fixtures.VcFixtures.vcExperianFraudM1a;
import static uk.gov.di.ipv.core.library.fixtures.VcFixtures.vcF2fPassportPhotoM1a;
import static uk.gov.di.ipv.core.library.fixtures.VcFixtures.vcSecurityCheckNoCis;
import static uk.gov.di.ipv.core.library.fixtures.VcFixtures.vcWebDrivingPermitDvaValid;
import static uk.gov.di.ipv.core.library.fixtures.VcFixtures.vcWebDrivingPermitDvlaValid;
import static uk.gov.di.ipv.core.library.fixtures.VcFixtures.vcWebPassportSuccessful;
import static uk.gov.di.ipv.core.library.gpg45.enums.Gpg45Profile.L1A;
import static uk.gov.di.ipv.core.library.gpg45.enums.Gpg45Profile.M1A;

@ExtendWith(MockitoExtension.class)
class EvcsServiceTest {
    private static final VerifiableCredential VC_DRIVING_PERMIT_TEST = vcWebDrivingPermitDvaValid();
    private static final VerifiableCredential VC_ADDRESS_TEST = vcAddressOne();
    private static final VerifiableCredential VC_PASSPORT_NON_DCMAW_SUCCESSFUL_TEST =
            vcWebPassportSuccessful();
    private static final VerifiableCredential VC_F2F = vcF2fPassportPhotoM1a();
    private static final List<VerifiableCredential> VERIFIABLE_CREDENTIALS =
            List.of(VC_DRIVING_PERMIT_TEST, VC_ADDRESS_TEST, vcExperianFraudM1a());
    private static final List<VerifiableCredential> VERIFIABLE_CREDENTIALS_ONE_EXIST_IN_EVCS =
            List.of(
                    VC_DRIVING_PERMIT_TEST,
                    VC_ADDRESS_TEST,
                    vcExperianFraudM1a(),
                    VC_PASSPORT_NON_DCMAW_SUCCESSFUL_TEST);
    private static final List<VerifiableCredential> VERIFIABLE_CREDENTIALS_ALL_EXIST_IN_EVCS =
            List.of(VC_DRIVING_PERMIT_TEST, VC_ADDRESS_TEST, VC_F2F);
    private static final String TEST_USER_ID = "a-user-id";
    private static final String TEST_GOVUK_SIGNIN_JOURNEY_ID = "test-govuk-signin-journey-id";

    private static final String TEST_EVCS_ACCESS_TOKEN = "TEST_EVCS_ACCESS_TOKEN";
    public static final String TEST_SI_JWT = "test.si.jwt";
    private static final List<EvcsGetUserVCDto> EVCS_GET_USER_VC_DTO =
            List.of(
                    new EvcsGetUserVCDto(
                            vcAddressTwo().getVcString(),
                            EvcsVCState.CURRENT,
                            Map.of(
                                    "reason", "testing",
                                    "txmaEventId", "txma-event-id-2",
                                    "timestampMs", "1714478033959")),
                    new EvcsGetUserVCDto(
                            vcWebDrivingPermitDvlaValid().getVcString(),
                            EvcsVCState.PENDING_RETURN,
                            Map.of(
                                    "reason", "testing",
                                    "txmaEventId", "txma-event-id-2",
                                    "timestampMs", "1714478033959")),
                    new EvcsGetUserVCDto(
                            VC_PASSPORT_NON_DCMAW_SUCCESSFUL_TEST.getVcString(),
                            EvcsVCState.CURRENT,
                            Map.of(
                                    "reason", "testing",
                                    "txmaEventId", "txma-event-id-2",
                                    "timestampMs", "1714478033959")));

    private static final VotMatchingResult.VotAndProfile STRONGEST_MATCHED_VOT =
            new VotMatchingResult.VotAndProfile(P1, Optional.of(L1A));
    private static final VotMatchingResult.VotAndProfile STRONGEST_MATCHED_VOT_P3 =
            new VotMatchingResult.VotAndProfile(P2, Optional.of(M1A));
    private static final Vot ACHIEVED_VOT = P1;

    @Captor ArgumentCaptor<EvcsPostIdentityDto> evcsPostIdentityDtoCaptor;
    @Captor ArgumentCaptor<EvcsCreateUserVCsRequestBody> evcsCreateRequestBodyCaptor;
    @Captor ArgumentCaptor<EvcsUpdateUserVCsRequestBody> evcsUpdateRequestBodyCaptor;

    @Mock EvcsClient mockEvcsClient;
    @Mock ConfigService mockConfigService;
    @Mock StoredIdentityService mockStoredIdentityService;
    @InjectMocks EvcsService evcsService;

    @Nested
    class StoreIdentityWithPost {
        @Test
        void testStoreIdentity_whenNoExistingEvcsUserVCs() throws Exception {
            // Arrange
            when(mockStoredIdentityService.getStoredIdentityForEvcs(any(), any(), any(), any()))
                    .thenReturn(new EvcsStoredIdentityDto(TEST_SI_JWT, P3));

            // Act
            evcsService.storeStoredIdentityRecordAndVcs(
                    TEST_USER_ID,
                    TEST_GOVUK_SIGNIN_JOURNEY_ID,
                    VERIFIABLE_CREDENTIALS,
                    List.of(),
                    STRONGEST_MATCHED_VOT_P3,
                    P2);

            // Assert
            verify(mockEvcsClient).storeUserIdentity(evcsPostIdentityDtoCaptor.capture());
            var evcsPostIdentityDto = evcsPostIdentityDtoCaptor.getValue();
            assertEquals(
                    3,
                    (evcsPostIdentityDto.vcs().stream()
                            .filter(vc -> vc.state().equals(EvcsVCState.CURRENT))
                            .count()));
            assertFalse(
                    evcsPostIdentityDto.vcs().stream()
                            .anyMatch(vc -> !vc.state().equals(EvcsVCState.CURRENT)));
            assertFalse(
                    evcsPostIdentityDto.vcs().stream()
                            .anyMatch(dto -> !dto.provenance().equals(ONLINE)));
            assertEquals(TEST_SI_JWT, evcsPostIdentityDto.si().jwt());
            assertEquals(P3, evcsPostIdentityDto.si().vot());
            assertEquals(TEST_USER_ID, evcsPostIdentityDto.userId());
            assertEquals(
                    TEST_GOVUK_SIGNIN_JOURNEY_ID, evcsPostIdentityDto.govuk_signin_journey_id());
        }

        @Test
        void testStoreCompleteIdentity_whenAllVCsExistInEvcs_withCurrentState() throws Exception {
            // Arrange
            when(mockStoredIdentityService.getStoredIdentityForEvcs(any(), any(), any(), any()))
                    .thenReturn(new EvcsStoredIdentityDto(TEST_SI_JWT, P3));
            var evcsGetUserVcsWithCurrentStateAllExistingDto =
                    List.of(
                            new EvcsGetUserVCDto(
                                    VC_ADDRESS_TEST.getVcString(),
                                    EvcsVCState.CURRENT,
                                    Map.of("reason", "testing")),
                            new EvcsGetUserVCDto(
                                    VC_DRIVING_PERMIT_TEST.getVcString(),
                                    EvcsVCState.CURRENT,
                                    Map.of("reason", "testing")),
                            new EvcsGetUserVCDto(
                                    VC_F2F.getVcString(),
                                    EvcsVCState.CURRENT,
                                    Map.of("reason", "testing")));

            // Act
            evcsService.storeStoredIdentityRecordAndVcs(
                    TEST_USER_ID,
                    TEST_GOVUK_SIGNIN_JOURNEY_ID,
                    VERIFIABLE_CREDENTIALS_ALL_EXIST_IN_EVCS,
                    evcsGetUserVcsWithCurrentStateAllExistingDto,
                    STRONGEST_MATCHED_VOT_P3,
                    P2);

            // Assert
            verify(mockEvcsClient, times(1)).storeUserIdentity(evcsPostIdentityDtoCaptor.capture());
            var evcsPostIdentityDto = evcsPostIdentityDtoCaptor.getValue();
            // We are passing null to omit vcs field
            // If VCs are present, EVCS expect at least 1 VC to be present in the list
            assertNull(evcsPostIdentityDto.vcs());
            assertEquals(TEST_SI_JWT, evcsPostIdentityDto.si().jwt());
            assertEquals(P3, evcsPostIdentityDto.si().vot());
            assertEquals(TEST_USER_ID, evcsPostIdentityDto.userId());
            assertNull(evcsPostIdentityDto.govuk_signin_journey_id());
        }

        @Test
        void testStoreCompleteIdentity_whenAllVCsExistInEvcs_inSession_withPendingReturnState()
                throws Exception {
            // Arrange
            when(mockStoredIdentityService.getStoredIdentityForEvcs(any(), any(), any(), any()))
                    .thenReturn(new EvcsStoredIdentityDto(TEST_SI_JWT, P3));
            List<EvcsGetUserVCDto> evcsGetUserVcsWithPendingAllExistingDto =
                    List.of(
                            new EvcsGetUserVCDto(
                                    VC_ADDRESS_TEST.getVcString(),
                                    EvcsVCState.PENDING_RETURN,
                                    Map.of("reason", "testing")),
                            new EvcsGetUserVCDto(
                                    VC_DRIVING_PERMIT_TEST.getVcString(),
                                    EvcsVCState.PENDING_RETURN,
                                    Map.of("reason", "testing")),
                            new EvcsGetUserVCDto(
                                    VC_F2F.getVcString(),
                                    EvcsVCState.PENDING_RETURN,
                                    Map.of("reason", "testing")));
            // Act
            evcsService.storeStoredIdentityRecordAndVcs(
                    TEST_USER_ID,
                    TEST_GOVUK_SIGNIN_JOURNEY_ID,
                    VERIFIABLE_CREDENTIALS_ALL_EXIST_IN_EVCS,
                    evcsGetUserVcsWithPendingAllExistingDto,
                    STRONGEST_MATCHED_VOT_P3,
                    P2);

            // Assert
            verify(mockEvcsClient, times(1)).storeUserIdentity(evcsPostIdentityDtoCaptor.capture());
            var evcsPostIdentityDto = evcsPostIdentityDtoCaptor.getValue();
            assertEquals(
                    3,
                    (evcsPostIdentityDto.vcs().stream()
                            .filter(vc -> vc.state().equals(EvcsVCState.CURRENT))
                            .count()));
            assertEquals(TEST_SI_JWT, evcsPostIdentityDto.si().jwt());
            assertEquals(P3, evcsPostIdentityDto.si().vot());
            assertEquals(TEST_USER_ID, evcsPostIdentityDto.userId());
            assertEquals(
                    TEST_GOVUK_SIGNIN_JOURNEY_ID, evcsPostIdentityDto.govuk_signin_journey_id());
        }

        @Test
        void testStoreCompleteIdentity_whenAllVCsExistInEvcs_notInSession_withPendingReturnState()
                throws Exception {
            // Arrange
            when(mockStoredIdentityService.getStoredIdentityForEvcs(any(), any(), any(), any()))
                    .thenReturn(new EvcsStoredIdentityDto(TEST_SI_JWT, P0));
            List<EvcsGetUserVCDto> evcsGetUserVcsWithPendingAllExistingDto =
                    List.of(
                            new EvcsGetUserVCDto(
                                    VC_ADDRESS_TEST.getVcString(),
                                    EvcsVCState.PENDING_RETURN,
                                    Map.of("reason", "testing")),
                            new EvcsGetUserVCDto(
                                    VC_DRIVING_PERMIT_TEST.getVcString(),
                                    EvcsVCState.PENDING_RETURN,
                                    Map.of("reason", "testing")),
                            new EvcsGetUserVCDto(
                                    VC_F2F.getVcString(),
                                    EvcsVCState.PENDING_RETURN,
                                    Map.of("reason", "testing")));
            // Act
            evcsService.storeStoredIdentityRecordAndVcs(
                    TEST_USER_ID,
                    TEST_GOVUK_SIGNIN_JOURNEY_ID,
                    List.of(),
                    evcsGetUserVcsWithPendingAllExistingDto,
                    null,
                    P0);

            // Assert
            verify(mockEvcsClient, times(1)).storeUserIdentity(evcsPostIdentityDtoCaptor.capture());
            var evcsPostIdentityDto = evcsPostIdentityDtoCaptor.getValue();
            assertEquals(
                    3,
                    (evcsPostIdentityDto.vcs().stream()
                            .filter(vc -> vc.state().equals(EvcsVCState.ABANDONED))
                            .count()));
            assertEquals(TEST_SI_JWT, evcsPostIdentityDto.si().jwt());
            assertEquals(P0, evcsPostIdentityDto.si().vot());
            assertEquals(TEST_USER_ID, evcsPostIdentityDto.userId());
            assertEquals(
                    TEST_GOVUK_SIGNIN_JOURNEY_ID, evcsPostIdentityDto.govuk_signin_journey_id());
        }
    }

    @Test
    void testStorePendingIdentity_for_incompleteF2F() throws Exception {
        // Act
        evcsService.storePendingIdentityWithPostVcs(
                TEST_USER_ID,
                TEST_GOVUK_SIGNIN_JOURNEY_ID,
                VERIFIABLE_CREDENTIALS_ONE_EXIST_IN_EVCS,
                List.of());

        // Assert
        verify(mockEvcsClient, never()).updateUserVcs(any());
        verify(mockEvcsClient).storeUserVcs(evcsCreateRequestBodyCaptor.capture());
        var requestBody = evcsCreateRequestBodyCaptor.getValue();
        assertFalse(
                requestBody.vcs().stream().anyMatch(dto -> !dto.state().equals(PENDING_RETURN)));
    }

    @Test
    void storePendingVcShouldStoreVcWithPendingReturnState() throws EvcsServiceException {
        // Act
        evcsService.storePendingVc(VC_ADDRESS_TEST, TEST_GOVUK_SIGNIN_JOURNEY_ID);

        // Assert
        verify(mockEvcsClient).storeUserVcs(evcsCreateRequestBodyCaptor.capture());
        var requestBody = evcsCreateRequestBodyCaptor.getValue();
        assertEquals(VC_ADDRESS_TEST.getUserId(), requestBody.userId());
        assertEquals(TEST_GOVUK_SIGNIN_JOURNEY_ID, requestBody.govuk_signin_journey_id());
        assertEquals(VC_ADDRESS_TEST.getVcString(), requestBody.vcs().get(0).vc());
        assertEquals(PENDING_RETURN, requestBody.vcs().get(0).state());
        assertEquals(OFFLINE, requestBody.vcs().get(0).provenance());
    }

    @Test
    void abandonPendingIdentityShouldUpdateStateToAbandoned() throws EvcsServiceException {
        // Arrange
        EvcsGetUserVCsDto evcsGetUserVcsWithPendingAllExistingDto =
                new EvcsGetUserVCsDto(
                        List.of(
                                new EvcsGetUserVCDto(
                                        VC_ADDRESS_TEST.getVcString(),
                                        EvcsVCState.PENDING_RETURN,
                                        Map.of("reason", "testing")),
                                new EvcsGetUserVCDto(
                                        vcExperianFraudM1a().getVcString(),
                                        EvcsVCState.PENDING_RETURN,
                                        Map.of("reason", "testing"))),
                        null);
        when(mockEvcsClient.getUserVcs(
                        TEST_USER_ID, TEST_EVCS_ACCESS_TOKEN, List.of(PENDING_RETURN)))
                .thenReturn(evcsGetUserVcsWithPendingAllExistingDto);

        // Act
        evcsService.abandonPendingIdentity(
                TEST_USER_ID, TEST_EVCS_ACCESS_TOKEN, TEST_GOVUK_SIGNIN_JOURNEY_ID);

        // Assert
        InOrder mockOrderVerifier = inOrder(mockEvcsClient);
        mockOrderVerifier
                .verify(mockEvcsClient)
                .getUserVcs(TEST_USER_ID, TEST_EVCS_ACCESS_TOKEN, List.of(PENDING_RETURN));
        mockOrderVerifier
                .verify(mockEvcsClient)
                .updateUserVcs(evcsUpdateRequestBodyCaptor.capture());
        var requestBody = evcsUpdateRequestBodyCaptor.getValue();
        assertEquals(TEST_USER_ID, requestBody.userId());
        assertEquals(TEST_GOVUK_SIGNIN_JOURNEY_ID, requestBody.govuk_signin_journey_id());
        assertEquals(
                2, requestBody.vcs().stream().filter(dto -> dto.state().equals(ABANDONED)).count());
    }

    @Test
    void testGetVerifiableCredentials() throws CredentialParseException, EvcsServiceException {
        // Arrange
        when(mockConfigService.getCimitComponentId())
                .thenReturn("https://cimit.stubs.account.gov.uk");
        when(mockConfigService.getIssuerCris())
                .thenReturn(
                        Map.of(
                                vcAddressM1a().getClaimsSet().getIssuer(),
                                Cri.ADDRESS,
                                vcWebPassportSuccessful().getClaimsSet().getIssuer(),
                                Cri.DCMAW));

        when(mockEvcsClient.getUserVcs(TEST_USER_ID, TEST_EVCS_ACCESS_TOKEN, List.of(CURRENT)))
                .thenReturn(
                        new EvcsGetUserVCsDto(
                                List.of(
                                        new EvcsGetUserVCDto(
                                                vcAddressM1a().getVcString(),
                                                EvcsVCState.CURRENT,
                                                null),
                                        new EvcsGetUserVCDto(
                                                vcWebPassportSuccessful().getVcString(),
                                                EvcsVCState.CURRENT,
                                                null)),
                                null));

        // Act
        var vcs =
                evcsService.getVerifiableCredentials(TEST_USER_ID, TEST_EVCS_ACCESS_TOKEN, CURRENT);
        // Assert
        assertEquals(
                2,
                (vcs.stream()
                        .filter(
                                vc ->
                                        vc.getCri().equals(Cri.ADDRESS)
                                                || vc.getCri().equals(Cri.DCMAW))
                        .count()));
    }

    @Test
    void testGetVerifiableCredentialsShouldErrorWhenCriNotFound() throws EvcsServiceException {
        // Arrange
        when(mockConfigService.getCimitComponentId())
                .thenReturn("https://cimit.stubs.account.gov.uk");
        when(mockConfigService.getIssuerCris()).thenReturn(Map.of());

        when(mockEvcsClient.getUserVcs(TEST_USER_ID, TEST_EVCS_ACCESS_TOKEN, List.of(CURRENT)))
                .thenReturn(
                        new EvcsGetUserVCsDto(
                                List.of(
                                        new EvcsGetUserVCDto(
                                                vcExperianFraudM1a().getVcString(),
                                                EvcsVCState.CURRENT,
                                                null),
                                        new EvcsGetUserVCDto(
                                                vcWebPassportSuccessful().getVcString(),
                                                EvcsVCState.CURRENT,
                                                null)),
                                null));

        // Act/Assert
        assertThrows(
                CredentialParseException.class,
                () ->
                        evcsService.getVerifiableCredentials(
                                TEST_USER_ID, TEST_EVCS_ACCESS_TOKEN, CURRENT));
    }

    @Test
    void getVerifiableCredentialsShouldReturnParsedVcsWhenGivenEvcsVcs() throws Exception {
        // Arrange
        when(mockConfigService.getCimitComponentId())
                .thenReturn("https://cimit.stubs.account.gov.uk");
        var evcsVcs =
                List.of(
                        new EvcsGetUserVCDto(vcAddressM1a().getVcString(), CURRENT, null),
                        new EvcsGetUserVCDto(
                                vcWebPassportSuccessful().getVcString(), CURRENT, null));

        when(mockConfigService.getIssuerCris())
                .thenReturn(
                        Map.of(
                                vcAddressM1a().getClaimsSet().getIssuer(),
                                Cri.ADDRESS,
                                vcWebPassportSuccessful().getClaimsSet().getIssuer(),
                                Cri.DCMAW));

        // Act
        var vcs = evcsService.getVerifiableCredentials(TEST_USER_ID, evcsVcs, CURRENT);
        // Assert
        assertEquals(
                2,
                (vcs.stream()
                        .filter(
                                vc ->
                                        vc.getCri().equals(Cri.ADDRESS)
                                                || vc.getCri().equals(Cri.DCMAW))
                        .count()));
    }

    @Test
    void getVerifiableCredentialsSupportsMultipleStates() throws Exception {
        // Arrange
        when(mockConfigService.getCimitComponentId())
                .thenReturn("https://cimit.stubs.account.gov.uk");
        var evcsVcs =
                List.of(
                        new EvcsGetUserVCDto(vcAddressM1a().getVcString(), CURRENT, null),
                        new EvcsGetUserVCDto(
                                vcWebPassportSuccessful().getVcString(), PENDING_RETURN, null));

        when(mockConfigService.getIssuerCris())
                .thenReturn(
                        Map.of(
                                vcAddressM1a().getClaimsSet().getIssuer(),
                                Cri.ADDRESS,
                                vcWebPassportSuccessful().getClaimsSet().getIssuer(),
                                Cri.DCMAW));

        // Act
        var vcs =
                evcsService.getVerifiableCredentials(
                        TEST_USER_ID, evcsVcs, CURRENT, PENDING_RETURN);
        // Assert
        assertEquals(
                2,
                (vcs.stream()
                        .filter(
                                vc ->
                                        vc.getCri().equals(Cri.ADDRESS)
                                                || vc.getCri().equals(Cri.DCMAW))
                        .count()));
    }

    @Test
    void getVerifiableCredentialsFiltersOutCimitVcs() throws Exception {
        // Arrange
        when(mockConfigService.getCimitComponentId())
                .thenReturn("https://cimit.stubs.account.gov.uk");
        var evcsVcs =
                List.of(
                        new EvcsGetUserVCDto(vcAddressM1a().getVcString(), CURRENT, null),
                        new EvcsGetUserVCDto(
                                vcWebPassportSuccessful().getVcString(), CURRENT, null),
                        new EvcsGetUserVCDto(vcSecurityCheckNoCis().getVcString(), CURRENT, null));

        when(mockConfigService.getIssuerCris())
                .thenReturn(
                        Map.of(
                                vcAddressM1a().getClaimsSet().getIssuer(),
                                Cri.ADDRESS,
                                vcWebPassportSuccessful().getClaimsSet().getIssuer(),
                                Cri.DCMAW));

        // Act
        var vcs = evcsService.getVerifiableCredentials(TEST_USER_ID, evcsVcs, CURRENT);
        // Assert
        assertEquals(2, vcs.size());
        assertEquals(
                2,
                (vcs.stream()
                        .filter(
                                vc ->
                                        vc.getCri().equals(Cri.ADDRESS)
                                                || vc.getCri().equals(Cri.DCMAW))
                        .count()));
    }

    private List<EvcsCreateUserVCsDto> extractVcsFromDto(
            EvcsVCState evcsVCState, EvcsPostIdentityDto evcsPostIdentityDto) {
        return evcsPostIdentityDto.vcs().stream()
                .filter(vc -> vc.state().equals(evcsVCState))
                .toList();
    }

    @Test
    void shouldStoreStoredIdentityRecordAndVcsAndUpdateStateOfExistingVcs()
            throws FailedToCreateStoredIdentityForEvcsException, EvcsServiceException {
        // Arrange
        var credentials = List.of(VC_ADDRESS_TEST);

        when(mockStoredIdentityService.getStoredIdentityForEvcs(
                        TEST_USER_ID, credentials, STRONGEST_MATCHED_VOT, ACHIEVED_VOT))
                .thenReturn(new EvcsStoredIdentityDto(TEST_SI_JWT, P1));

        // Act
        evcsService.storeStoredIdentityRecordAndVcs(
                TEST_USER_ID,
                TEST_GOVUK_SIGNIN_JOURNEY_ID,
                credentials,
                EVCS_GET_USER_VC_DTO,
                STRONGEST_MATCHED_VOT,
                ACHIEVED_VOT);

        // Assert
        verify(mockEvcsClient, times(1)).storeUserIdentity(evcsPostIdentityDtoCaptor.capture());

        assertEquals(TEST_SI_JWT, evcsPostIdentityDtoCaptor.getValue().si().jwt());
        assertEquals(P1, evcsPostIdentityDtoCaptor.getValue().si().vot());
        assertEquals(4, evcsPostIdentityDtoCaptor.getValue().vcs().size());

        var evcsPostIdentityDto = evcsPostIdentityDtoCaptor.getValue();
        var abandonedVcsCount = extractVcsFromDto(ABANDONED, evcsPostIdentityDto).size();
        var historicVcsCount = extractVcsFromDto(HISTORIC, evcsPostIdentityDto).size();
        var currentVcsCount = extractVcsFromDto(CURRENT, evcsPostIdentityDto).size();

        assertEquals(1, abandonedVcsCount);
        assertEquals(2, historicVcsCount);
        assertEquals(1, currentVcsCount);
        assertEquals(TEST_SI_JWT, evcsPostIdentityDto.si().jwt());
        assertEquals(P1, evcsPostIdentityDto.si().vot());
        assertEquals(TEST_USER_ID, evcsPostIdentityDto.userId());
        assertEquals(TEST_GOVUK_SIGNIN_JOURNEY_ID, evcsPostIdentityDto.govuk_signin_journey_id());
    }

    @Test
    void shouldStoreStoredIdentityRecordAndPendingReturnVcsExistingInEvcs()
            throws FailedToCreateStoredIdentityForEvcsException, EvcsServiceException {
        // Arrange
        var credentials = List.of(VC_ADDRESS_TEST);

        var existingGetUserVcDto =
                List.of(
                        new EvcsGetUserVCDto(
                                VC_ADDRESS_TEST.getVcString(),
                                PENDING_RETURN,
                                Map.of("reason", "testing")));

        when(mockStoredIdentityService.getStoredIdentityForEvcs(
                        TEST_USER_ID, credentials, STRONGEST_MATCHED_VOT, ACHIEVED_VOT))
                .thenReturn(new EvcsStoredIdentityDto(TEST_SI_JWT, P1));

        // Act
        evcsService.storeStoredIdentityRecordAndVcs(
                TEST_USER_ID,
                TEST_GOVUK_SIGNIN_JOURNEY_ID,
                credentials,
                existingGetUserVcDto,
                STRONGEST_MATCHED_VOT,
                ACHIEVED_VOT);

        // Assert
        verify(mockEvcsClient, times(1)).storeUserIdentity(evcsPostIdentityDtoCaptor.capture());
        var extractVcsFromDto = evcsPostIdentityDtoCaptor.getValue();

        assertEquals(TEST_SI_JWT, extractVcsFromDto.si().jwt());
        assertEquals(P1, extractVcsFromDto.si().vot());
        assertEquals(1, extractVcsFromDto.vcs().size());
        assertEquals(CURRENT, extractVcsFromDto.vcs().getFirst().state());
    }

    @Test
    void shouldInvalidateStoredIdentityRecord() throws Exception {
        // Act
        evcsService.invalidateStoredIdentityRecord(TEST_USER_ID);

        // Assert
        verify(mockEvcsClient, times(1)).invalidateStoredIdentityRecord(TEST_USER_ID);
    }

    @Test
    void markHistoricInEvcsShouldUpdateEvcsWithHistoricVcs() throws Exception {
        // Act
        evcsService.markHistoricInEvcs(
                TEST_USER_ID, TEST_GOVUK_SIGNIN_JOURNEY_ID, List.of(VC_DRIVING_PERMIT_TEST));

        // Assert
        verify(mockEvcsClient, times(1)).updateUserVcs(evcsUpdateRequestBodyCaptor.capture());
        var requestBody = evcsUpdateRequestBodyCaptor.getValue();
        assertEquals(TEST_USER_ID, requestBody.userId());
        assertEquals(TEST_GOVUK_SIGNIN_JOURNEY_ID, requestBody.govuk_signin_journey_id());
        assertEquals(
                1, requestBody.vcs().stream().filter(dto -> dto.state().equals(HISTORIC)).count());
    }

    @Test
    void markHistoricInEvcsShouldNotCallEvcsIfGivenEmptyList() throws Exception {
        // Act
        evcsService.markHistoricInEvcs(TEST_USER_ID, TEST_GOVUK_SIGNIN_JOURNEY_ID, List.of());

        // Assert
        verify(mockEvcsClient, never()).updateUserVcs(any());
    }
}
