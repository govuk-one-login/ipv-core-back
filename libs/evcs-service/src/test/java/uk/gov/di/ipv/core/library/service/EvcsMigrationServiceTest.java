package uk.gov.di.ipv.core.library.service;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.Captor;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import uk.gov.di.ipv.core.library.domain.VerifiableCredential;
import uk.gov.di.ipv.core.library.verifiablecredential.service.VerifiableCredentialService;

import java.util.List;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.verify;
import static uk.gov.di.ipv.core.library.fixtures.VcFixtures.vcAddressEmpty;
import static uk.gov.di.ipv.core.library.fixtures.VcFixtures.vcDrivingPermit;
import static uk.gov.di.ipv.core.library.fixtures.VcFixtures.vcFraudNotExpired;

@ExtendWith(MockitoExtension.class)
class EvcsMigrationServiceTest {
    private static final String TEST_USER_ID = "a-user-id";

    @Captor ArgumentCaptor<List<VerifiableCredential>> vcsToUpdateCaptor;

    @Mock EvcsService mockEvcsService;
    @Mock VerifiableCredentialService mockVerifiableCredentialService;
    @InjectMocks EvcsMigrationService evcsMigrationService;

    @Test
    void testMigrateExistingIdentity() throws Exception {
        var vcs = List.of(vcDrivingPermit(), vcAddressEmpty(), vcFraudNotExpired());

        evcsMigrationService.migrateExistingIdentity(TEST_USER_ID, vcs);

        verify(mockEvcsService).storeMigratedIdentity(TEST_USER_ID, vcs);
        verify(mockVerifiableCredentialService).updateIdentity(vcsToUpdateCaptor.capture());
        vcsToUpdateCaptor.getValue().forEach(vc -> assertNotNull(vc.getMigrated()));
    }
}
