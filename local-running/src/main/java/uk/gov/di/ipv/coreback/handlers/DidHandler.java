package uk.gov.di.ipv.coreback.handlers;

import com.nimbusds.jose.jwk.ECKey;
import io.javalin.http.Context;
import uk.gov.di.ipv.core.library.fixtures.TestFixtures;
import uk.gov.di.ipv.coreback.domain.DidDocument;

import java.text.ParseException;

public class DidHandler {
    private DidHandler() {}

    public static void did(Context ctx) throws ParseException {
        var signingKey = ECKey.parse(TestFixtures.TEST_EC_PUBLIC_SIGNING_KEY);

        ctx.json(new DidDocument(signingKey.toPublicJWK()));
    }
}
