package uk.gov.di.ipv.core.library.service;

import software.amazon.lambda.powertools.tracing.Tracing;
import uk.gov.di.ipv.core.library.annotations.ExcludeFromGeneratedCoverageReport;
import uk.gov.di.ipv.core.library.client.EvcsClient;
import uk.gov.di.ipv.core.library.domain.VerifiableCredential;
import uk.gov.di.ipv.core.library.dto.EvcsCreateUserVCsDto;
import uk.gov.di.ipv.core.library.exception.EvcsServiceException;

import java.util.List;

import static uk.gov.di.ipv.core.library.enums.EvcsVCState.CURRENT;

public class EvcsMigrationService {
    private final EvcsClient evcsClient;

    @ExcludeFromGeneratedCoverageReport
    public EvcsMigrationService(EvcsClient evcsClient) {
        this.evcsClient = evcsClient;
    }

    @ExcludeFromGeneratedCoverageReport
    public EvcsMigrationService(ConfigService configService) {
        this.evcsClient = new EvcsClient(configService);
    }

    @Tracing
    public void migrateExistingIdentity(String userId, List<VerifiableCredential> credentials)
            throws EvcsServiceException {
        List<EvcsCreateUserVCsDto> userVCsForEvcs =
                credentials.stream()
                        .filter(credential -> credential.getMigrated() != null)
                        .map(vc -> new EvcsCreateUserVCsDto(vc.getVcString(), CURRENT, null, null))
                        .toList();
        evcsClient.storeUserVCs(userId, userVCsForEvcs);
    }
}
