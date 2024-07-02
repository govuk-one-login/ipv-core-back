package uk.gov.di.ipv.core.library.service;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import software.amazon.lambda.powertools.tracing.Tracing;
import uk.gov.di.ipv.core.library.annotations.ExcludeFromGeneratedCoverageReport;
import uk.gov.di.ipv.core.library.domain.VerifiableCredential;
import uk.gov.di.ipv.core.library.exception.EvcsServiceException;
import uk.gov.di.ipv.core.library.exceptions.VerifiableCredentialException;
import uk.gov.di.ipv.core.library.helpers.LogHelper;
import uk.gov.di.ipv.core.library.verifiablecredential.service.VerifiableCredentialService;

import java.time.Instant;
import java.util.List;

public class EvcsMigrationService {
    private static final Logger LOGGER = LogManager.getLogger();
    private final EvcsService evcsService;
    private final VerifiableCredentialService verifiableCredentialService;

    @ExcludeFromGeneratedCoverageReport
    public EvcsMigrationService(
            EvcsService evcsService, VerifiableCredentialService verifiableCredentialService) {
        this.evcsService = evcsService;
        this.verifiableCredentialService = verifiableCredentialService;
    }

    @ExcludeFromGeneratedCoverageReport
    public EvcsMigrationService(ConfigService configService) {
        this.evcsService = new EvcsService(configService);
        this.verifiableCredentialService = new VerifiableCredentialService(configService);
    }

    @Tracing
    public void migrateExistingIdentity(String userId, List<VerifiableCredential> credentials)
            throws EvcsServiceException, VerifiableCredentialException {
        LOGGER.info(LogHelper.buildLogMessage("Migrating existing user VCs to Evcs."));
        evcsService.storeMigratedIdentity(userId, credentials);
        credentials.forEach(credential -> credential.setMigrated(Instant.now()));
        verifiableCredentialService.updateIdentity(credentials);
        LOGGER.info(LogHelper.buildLogMessage("Migrated existing user VCs to Evcs."));
    }
}
