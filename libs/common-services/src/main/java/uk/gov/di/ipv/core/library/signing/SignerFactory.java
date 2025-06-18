package uk.gov.di.ipv.core.library.signing;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.jwk.ECKey;
import software.amazon.awssdk.http.apache.ApacheHttpClient;
import software.amazon.awssdk.services.kms.KmsClient;
import uk.gov.di.ipv.core.library.annotations.ExcludeFromGeneratedCoverageReport;
import uk.gov.di.ipv.core.library.service.ConfigService;

import java.text.ParseException;

import static software.amazon.awssdk.regions.Region.EU_WEST_2;
import static uk.gov.di.ipv.core.library.config.ConfigurationVariable.SIGNING_KEY_ID;
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
                        .httpClientBuilder(ApacheHttpClient.builder())
                        .build();
    }

    public CoreSigner getSigner() {
        if (ConfigService.isLocal()) {
            try {
                return new LocalECDSASigner(ECKey.parse(configService.getSecret(SIGNING_KEY_JWK)));
            } catch (JOSEException | ParseException e) {
                throw new IllegalArgumentException("Could not parse signing key", e);
            }
        }
        return new KmsEs256Signer(kmsClient, configService.getParameter(SIGNING_KEY_ID));
    }
}
