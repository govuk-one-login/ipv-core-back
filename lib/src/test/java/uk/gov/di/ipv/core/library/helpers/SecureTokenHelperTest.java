package uk.gov.di.ipv.core.library.helpers;

import org.junit.jupiter.api.Test;

import java.util.Base64;

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static uk.gov.di.ipv.core.library.helpers.SecureTokenHelper.BYTES_OF_ENTROPY;

class SecureTokenHelperTest {
    @Test
    void generateShouldGiveAB64StringOfKnownLength() {
        String token = SecureTokenHelper.generate();

        byte[] bytes = assertDoesNotThrow(() -> Base64.getUrlDecoder().decode(token));
        assertEquals(BYTES_OF_ENTROPY, bytes.length);
    }
}
