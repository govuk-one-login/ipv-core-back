package uk.gov.di.ipv.coreback.domain;

import com.fasterxml.jackson.annotation.JsonProperty;
import com.nimbusds.jose.jwk.JWK;
import lombok.Getter;

import java.util.List;
import java.util.Map;

@Getter
public class DidDocument {
    @JsonProperty(value = "@context")
    private final List<String> context = List.of("https://www.w3.org/ns/did/v1");

    @JsonProperty
    private String id = "did:web:api.identity.build.account.gov.uk:.well-known/stored-identity";

    @JsonProperty(value = "assertionMethod")
    private List<DidAssertionMethod> didAssertionMethod;

    public DidDocument(JWK publicKeyJwk) {
        this.didAssertionMethod = List.of(new DidAssertionMethod(publicKeyJwk.toJSONObject()));
    }

    @Getter
    public static class DidAssertionMethod {
        @JsonProperty
        private String id =
                "did:web:api.identity.build.account.gov.uk:.well-known/stored-identity#key-id";

        @JsonProperty private String type = "JsonWebKey2020";

        @JsonProperty
        private String controller =
                "did:web:api.identity.build.account.gov.uk:.well-known/stored-identity";

        @JsonProperty private Map<String, Object> publicKeyJwk;

        public DidAssertionMethod(Map<String, Object> publicKeyJwk) {
            this.publicKeyJwk = publicKeyJwk;
        }
    }
}
