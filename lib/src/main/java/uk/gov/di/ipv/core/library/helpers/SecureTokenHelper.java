package uk.gov.di.ipv.core.library.helpers;

import java.security.SecureRandom;
import java.util.Base64;

public class SecureTokenHelper {

    private SecureTokenHelper() {
        throw new IllegalStateException("Utility class");
    }

    public static final int BYTES_OF_ENTROPY = 32;
    private static final SecureRandom random = new SecureRandom();
    private static final Base64.Encoder b64Encoder = Base64.getUrlEncoder().withoutPadding();

    public static String generate() {
        // Returns a B64 encoded random string with 256 bits of entropy
        // For example: ScnF4dGXthZYXS_5k85ObEoSU04W-H3qa_p6npv2ZUY
        byte[] buffer = new byte[BYTES_OF_ENTROPY];
        random.nextBytes(buffer);

        return b64Encoder.encodeToString(buffer);
    }
}
