package uk.gov.di.ipv.core.library.kmses256signer;

import com.amazonaws.services.kms.AWSKMS;
import com.amazonaws.services.kms.AWSKMSClientBuilder;
import com.nimbusds.jose.JWSSigner;
import uk.gov.di.ipv.core.library.annotations.ExcludeFromGeneratedCoverageReport;

@ExcludeFromGeneratedCoverageReport
public class KmsEs256SignerFactory {

    private final AWSKMS kmsClient;

    public KmsEs256SignerFactory() {
        this.kmsClient = AWSKMSClientBuilder.defaultClient();
    }

    public JWSSigner getSigner(String kmsKeyId) {
        return new KmsEs256Signer(kmsClient, kmsKeyId);
    }
}
