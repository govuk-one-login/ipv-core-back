package uk.gov.di.ipv.coreback.handlers;

import com.nimbusds.jose.jwk.ECKey;
import io.javalin.http.Context;
import uk.gov.di.ipv.core.library.config.ConfigurationVariable;
import uk.gov.di.ipv.core.library.service.ConfigService;
import uk.gov.di.ipv.coreback.domain.DidDocument;

import java.text.ParseException;

public class DidHandler {
    private final ConfigService configService;

    public DidHandler() {
        this.configService = ConfigService.create();
    }

    public void did(Context ctx) throws ParseException {
        var signingKey =
                ECKey.parse(configService.getSecret(ConfigurationVariable.SIGNING_KEY_JWK));

        ctx.json(new DidDocument(signingKey.toPublicJWK()));
    }
}
