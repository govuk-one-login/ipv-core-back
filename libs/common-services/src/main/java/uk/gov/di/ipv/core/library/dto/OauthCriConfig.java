package uk.gov.di.ipv.core.library.dto;

import com.nimbusds.jose.jwk.RSAKey;
import lombok.EqualsAndHashCode;
import lombok.Getter;
import lombok.NoArgsConstructor;
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
    private URI tokenUrl;
    private URI authorizeUrl;
    private String clientId;
    private String encryptionKey;
    private URI clientCallbackUrl;
    private boolean requiresAdditionalEvidence;
    private URI jwksUrl;

    public RSAKey getParsedEncryptionKey() throws ParseException {
        return RSAKey.parse(encryptionKey);
    }
}
