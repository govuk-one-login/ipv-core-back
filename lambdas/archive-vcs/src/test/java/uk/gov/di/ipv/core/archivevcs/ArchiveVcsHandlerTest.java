package uk.gov.di.ipv.core.archivevcs;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import uk.gov.di.ipv.core.library.service.ConfigService;
import uk.gov.di.ipv.core.library.verifiablecredential.service.VerifiableCredentialService;

import static org.junit.jupiter.api.Assertions.assertNotNull;

@ExtendWith(MockitoExtension.class)
class ReplayCimitVcsHandlerTest {
    @Mock private ConfigService configService;
    @Mock private VerifiableCredentialService mockVerifiableCredentialService;
    @InjectMocks private ArchiveVcsHandler archiveVcsHandler;

    @Test
    void shouldPass() {
        archiveVcsHandler.handleRequest(null, null, null);
        assertNotNull(configService);
        assertNotNull(mockVerifiableCredentialService);
    }
}
