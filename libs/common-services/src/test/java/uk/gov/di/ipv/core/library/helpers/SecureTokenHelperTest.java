package uk.gov.di.ipv.core.library.helpers;

import org.junit.jupiter.api.Test;

import java.util.Base64;

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertEquals;

class SecureTokenHelperTest {
    private static final int BYTES_OF_ENTROPY = 32;

    @Test
    void generateShouldGiveAB64StringOfKnownLength() {
        String token = SecureTokenHelper.generate();

        byte[] bytes = assertDoesNotThrow(() -> Base64.getUrlDecoder().decode(token));
        assertEquals(BYTES_OF_ENTROPY, bytes.length);
    }
}
