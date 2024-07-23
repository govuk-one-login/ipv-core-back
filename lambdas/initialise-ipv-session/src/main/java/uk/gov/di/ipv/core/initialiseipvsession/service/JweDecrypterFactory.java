package uk.gov.di.ipv.core.initialiseipvsession.service;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWEDecrypter;
import com.nimbusds.jose.crypto.RSADecrypter;
import com.nimbusds.jose.jwk.RSAKey;
import uk.gov.di.ipv.core.library.service.ConfigService;

import java.text.ParseException;

import static uk.gov.di.ipv.core.library.config.ConfigurationVariable.JAR_ENCRYPTION_KEY_JWK;

public class JweDecrypterFactory {
    private JweDecrypterFactory() {
        throw new IllegalStateException("Utility class");
    }

    public static JWEDecrypter create(ConfigService configService) {
        if (ConfigService.isLocal()) {
            try {
                return new RSADecrypter(
                        RSAKey.parse(configService.getSecret(JAR_ENCRYPTION_KEY_JWK)));
            } catch (JOSEException | ParseException e) {
                throw new IllegalArgumentException("Could not parse encryption key", e);
            }
        }
        return new KmsRsaDecrypter(configService);
    }
}
