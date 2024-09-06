package uk.gov.di.ipv.coreback.handlers;

import com.nimbusds.jose.jwk.ECKey;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.RSAKey;
import io.javalin.http.Context;
import uk.gov.di.ipv.core.library.config.ConfigurationVariable;
import uk.gov.di.ipv.core.library.service.ConfigService;

import java.text.ParseException;
import java.util.List;

public class JwksHandler {
    private final ConfigService configService;

    public JwksHandler() {
        this.configService = ConfigService.create();
    }

    public void jwks(Context ctx) throws ParseException {
        var signingKey =
                ECKey.parse(configService.getSecret(ConfigurationVariable.SIGNING_KEY_JWK));
        var encryptionKey =
                RSAKey.parse(configService.getSecret(ConfigurationVariable.JAR_ENCRYPTION_KEY_JWK));

        var jwks = new JWKSet(List.of(signingKey, encryptionKey));

        ctx.json(jwks.toJSONObject(true));
    }
}
