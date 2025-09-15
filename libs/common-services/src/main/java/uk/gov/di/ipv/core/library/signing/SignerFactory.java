package uk.gov.di.ipv.core.library.signing;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.jwk.ECKey;
import software.amazon.awssdk.http.crt.AwsCrtHttpClient;
import software.amazon.awssdk.services.kms.KmsClient;
import uk.gov.di.ipv.core.library.annotations.ExcludeFromGeneratedCoverageReport;
import uk.gov.di.ipv.core.library.service.ConfigService;

import java.text.ParseException;
import java.util.UUID;

import static software.amazon.awssdk.regions.Region.EU_WEST_2;
import static uk.gov.di.ipv.core.library.config.ConfigurationVariable.SIGNING_KEY_JWK;

@ExcludeFromGeneratedCoverageReport
public class SignerFactory {

    private final ConfigService configService;
    private final KmsClient kmsClient;

    public SignerFactory(ConfigService configService) {
        this.configService = configService;
        this.kmsClient =
                KmsClient.builder()
                        .region(EU_WEST_2)
                        .httpClientBuilder(AwsCrtHttpClient.builder())
                        .build();
    }

    public CoreSigner getSigner() {
        if (ConfigService.isLocal()) {
            try {
                return new LocalECDSASigner(ECKey.parse(configService.getSecret(SIGNING_KEY_JWK)));
            } catch (JOSEException | java.text.ParseException e) {
                throw new IllegalArgumentException("Could not parse signing key", e);
            }
        }
        UUID id = configService.getConfiguration().getSelf().getSigningKeyId();
        return new KmsEs256Signer(kmsClient, id.toString());
    }

    public CoreSigner getSisSigner() {
        if (ConfigService.isLocal()) {
            try {
                return new LocalECDSASigner(ECKey.parse(configService.getSecret(SIGNING_KEY_JWK)));
            } catch (JOSEException | ParseException e) {
                throw new IllegalArgumentException("Could not parse signing key", e);
            }
        }
        UUID id = configService.getConfiguration().getSelf().getSisSigningKeyId();
        return new KmsEs256Signer(kmsClient, id.toString());
    }
}
