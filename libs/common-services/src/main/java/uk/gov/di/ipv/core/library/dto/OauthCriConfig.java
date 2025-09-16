package uk.gov.di.ipv.core.library.dto;

import com.fasterxml.jackson.annotation.JsonIgnore;
import com.nimbusds.jose.jwk.RSAKey;
import lombok.EqualsAndHashCode;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.NonNull;
import lombok.Setter;
import lombok.experimental.SuperBuilder;
import uk.gov.di.ipv.core.library.annotations.ExcludeFromGeneratedCoverageReport;

import java.net.URI;
import java.text.ParseException;

@Getter
@Setter
@NoArgsConstructor
@SuperBuilder
@EqualsAndHashCode(callSuper = true)
@ExcludeFromGeneratedCoverageReport
public class OauthCriConfig extends RestCriConfig {
    @NonNull private URI tokenUrl;
    @NonNull private String clientId;
    private URI authorizeUrl;
    private String encryptionKey;
    private URI clientCallbackUrl;
    private boolean requiresAdditionalEvidence;
    private URI jwksUrl;

    @JsonIgnore
    public RSAKey getParsedEncryptionKey() throws ParseException {
        return RSAKey.parse(encryptionKey);
    }
}
