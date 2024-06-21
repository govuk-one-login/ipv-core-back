package uk.gov.di.ipv.core.library.kmses256signer;

import com.nimbusds.jose.JWSSigner;
import software.amazon.awssdk.http.crt.AwsCrtHttpClient;
import software.amazon.awssdk.services.kms.KmsClient;
import uk.gov.di.ipv.core.library.annotations.ExcludeFromGeneratedCoverageReport;

import static software.amazon.awssdk.regions.Region.EU_WEST_2;

@ExcludeFromGeneratedCoverageReport
public class KmsEs256SignerFactory {

    private final KmsClient kmsClient;

    public KmsEs256SignerFactory() {
        this.kmsClient =
                KmsClient.builder()
                        .region(EU_WEST_2)
                        .httpClientBuilder(AwsCrtHttpClient.builder())
                        .build();
    }

    public JWSSigner getSigner(String kmsKeyId) {
        return new KmsEs256Signer(kmsClient, kmsKeyId);
    }
}
