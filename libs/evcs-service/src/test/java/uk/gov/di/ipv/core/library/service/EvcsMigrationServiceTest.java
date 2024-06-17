package uk.gov.di.ipv.core.library.service;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import uk.gov.di.ipv.core.library.domain.VerifiableCredential;
import uk.gov.di.ipv.core.library.verifiablecredential.service.VerifiableCredentialService;

import java.time.Instant;
import java.util.List;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.verify;
import static uk.gov.di.ipv.core.library.domain.Cri.EXPERIAN_FRAUD;
import static uk.gov.di.ipv.core.library.fixtures.VcFixtures.M1A_EXPERIAN_FRAUD_VC;
import static uk.gov.di.ipv.core.library.fixtures.VcFixtures.VC_ADDRESS;
import static uk.gov.di.ipv.core.library.fixtures.VcFixtures.vcDrivingPermit;

@ExtendWith(MockitoExtension.class)
class EvcsMigrationServiceTest {
    private static final String TEST_USER_ID = "a-user-id";
    private static final String EVCS_TEST_TOKEN = "evcsTestToken";
    private static final List<VerifiableCredential> VCS =
            List.of(vcDrivingPermit(), VC_ADDRESS, M1A_EXPERIAN_FRAUD_VC);

    @Mock EvcsService mockEvcsService;
    @Mock VerifiableCredentialService mockVerifiableCredentialService;
    @InjectMocks EvcsMigrationService evcsMigrationService;

    @Test
    void testMigrateExistingIdentity() throws Exception {
        VCS.forEach(
                credential -> {
                    if (credential.getCriId().equals(EXPERIAN_FRAUD.getId())) {
                        credential.setMigrated(null);
                    } else {
                        credential.setMigrated(Instant.now());
                    }
                });
        ArgumentCaptor<List<VerifiableCredential>> vcsToUpdateCaptor =
                ArgumentCaptor.forClass(List.class);

        evcsMigrationService.migrateExistingIdentity(TEST_USER_ID, VCS, EVCS_TEST_TOKEN);

        verify(mockEvcsService).storeCompletedIdentity(TEST_USER_ID, VCS, EVCS_TEST_TOKEN);
        verify(mockVerifiableCredentialService).updateIdentity(vcsToUpdateCaptor.capture());
        vcsToUpdateCaptor.getValue().forEach(vc -> assertNotNull(vc.getMigrated()));
    }
}
