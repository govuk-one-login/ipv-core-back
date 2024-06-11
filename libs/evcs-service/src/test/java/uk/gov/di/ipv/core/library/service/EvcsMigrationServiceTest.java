package uk.gov.di.ipv.core.library.service;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.Captor;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import uk.gov.di.ipv.core.library.client.EvcsClient;
import uk.gov.di.ipv.core.library.domain.VerifiableCredential;
import uk.gov.di.ipv.core.library.dto.EvcsCreateUserVCsDto;
import uk.gov.di.ipv.core.library.enums.EvcsVCState;

import java.time.Instant;
import java.util.List;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.verify;
import static uk.gov.di.ipv.core.library.domain.CriConstants.EXPERIAN_FRAUD_CRI;
import static uk.gov.di.ipv.core.library.fixtures.VcFixtures.M1A_EXPERIAN_FRAUD_VC;
import static uk.gov.di.ipv.core.library.fixtures.VcFixtures.VC_ADDRESS;
import static uk.gov.di.ipv.core.library.fixtures.VcFixtures.vcDrivingPermit;

@ExtendWith(MockitoExtension.class)
class EvcsMigrationServiceTest {
    private static final String TEST_USER_ID = "a-user-id";
    private static final List<VerifiableCredential> VCS =
            List.of(vcDrivingPermit(), VC_ADDRESS, M1A_EXPERIAN_FRAUD_VC);

    @Captor ArgumentCaptor<List<EvcsCreateUserVCsDto>> evcsCreateUserVCsDtosCaptor;
    @Mock EvcsClient mockEvcsClient;
    @InjectMocks EvcsMigrationService evcsMigrationService;

    @Test
    void testMigrateExistingIdentity() {
        VCS.forEach(
                credential -> {
                    if (credential.getCriId().equals(EXPERIAN_FRAUD_CRI)) {
                        credential.setMigrated(null);
                    } else {
                        credential.setMigrated(Instant.now());
                    }
                });

        evcsMigrationService.migrateExistingIdentity(TEST_USER_ID, VCS);

        verify(mockEvcsClient).storeUserVCs(any(), evcsCreateUserVCsDtosCaptor.capture());
        var userVCsForEvcs = evcsCreateUserVCsDtosCaptor.getValue();
        assertEquals(
                2,
                (userVCsForEvcs.stream()
                        .filter(dto -> dto.state().equals(EvcsVCState.CURRENT))
                        .count()));
        assertFalse(
                userVCsForEvcs.stream().anyMatch(dto -> !dto.state().equals(EvcsVCState.CURRENT)));
    }
}
