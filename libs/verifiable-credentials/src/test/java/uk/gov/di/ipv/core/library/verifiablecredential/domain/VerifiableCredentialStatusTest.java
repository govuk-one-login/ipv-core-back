package uk.gov.di.ipv.core.library.verifiablecredential.domain;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;

class VerifiableCredentialStatusTest {
    @Test
    void shouldGetVerifiableCredentialStatusFromStatusString() {
        var verifiableCredentialStatus = VerifiableCredentialStatus.fromStatusString("pending");
        assertEquals(VerifiableCredentialStatus.PENDING, verifiableCredentialStatus);
    }

    @Test
    void shouldReturnNullForUnknownStatus() {
        var verifiableCredentialStatus =
                VerifiableCredentialStatus.fromStatusString("invalid_status");
        assertNull(verifiableCredentialStatus);
    }
}
