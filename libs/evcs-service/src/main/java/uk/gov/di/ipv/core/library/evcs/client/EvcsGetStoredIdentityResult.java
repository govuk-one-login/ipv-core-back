package uk.gov.di.ipv.core.library.evcs.client;

import uk.gov.di.ipv.core.library.evcs.dto.EvcsStoredIdentityCheckDto;

public record EvcsGetStoredIdentityResult(
        boolean requestSucceeded,
        boolean identityWasFound,
        EvcsStoredIdentityCheckDto identityDetails) {}
