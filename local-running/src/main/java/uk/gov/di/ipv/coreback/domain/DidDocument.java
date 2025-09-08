package uk.gov.di.ipv.coreback.domain;

import com.fasterxml.jackson.annotation.JsonProperty;
import com.nimbusds.jose.jwk.JWK;
import lombok.Data;

import java.util.List;

@Data
public class DidDocument {
    @JsonProperty(value = "@context")
    private static final List<String> context = List.of("https://www.w3.org/ns/did/v1");

    private static final String id =
            "did:web:api.identity.build.account.gov.uk:.well-known/stored-identity";

    private List<DidVerificationMethod> didVerificationMethod;

    public DidDocument(JWK publicKeyJwk) {
        this.didVerificationMethod = List.of(new DidVerificationMethod(publicKeyJwk));
    }

    public class DidVerificationMethod {
        private static String id =
                "did:web:api.identity.build.account.gov.uk:.well-known/stored-identity#key-id";
        private static String type = "JsonWebKey2020";
        private static String controller =
                "did:web:api.identity.build.account.gov.uk:.well-known/stored-identity";
        private JWK publicKeyJwk;

        public DidVerificationMethod(JWK publicKeyJwk) {
            this.publicKeyJwk = publicKeyJwk;
        }
    }
}
