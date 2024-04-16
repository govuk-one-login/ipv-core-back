package uk.gov.di.ipv.core.library.kmses256signer;

import com.nimbusds.jose.JWSSigner;
import software.amazon.awssdk.auth.credentials.EnvironmentVariableCredentialsProvider;
import software.amazon.awssdk.services.kms.KmsClient;
import uk.gov.di.ipv.core.library.annotations.ExcludeFromGeneratedCoverageReport;

import static software.amazon.awssdk.regions.Region.EU_WEST_2;

@ExcludeFromGeneratedCoverageReport
public class KmsEs256SignerFactory {

    private final KmsClient kmsClient;

    public KmsEs256SignerFactory() {
        this.kmsClient =
                KmsClient.builder()
                        .credentialsProvider(EnvironmentVariableCredentialsProvider.create())
                        .region(EU_WEST_2)
                        .build();
    }

    public JWSSigner getSigner(String kmsKeyId) {
        return new KmsEs256Signer(kmsClient, kmsKeyId);
    }
}
