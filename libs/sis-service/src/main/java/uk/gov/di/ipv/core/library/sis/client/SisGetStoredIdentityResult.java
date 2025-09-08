package uk.gov.di.ipv.core.library.sis.client;

import uk.gov.di.ipv.core.library.sis.dto.SisStoredIdentityCheckDto;

public record SisGetStoredIdentityResult(
        boolean requestSucceeded,
        boolean identityWasFound,
        SisStoredIdentityCheckDto identityDetails) {}
