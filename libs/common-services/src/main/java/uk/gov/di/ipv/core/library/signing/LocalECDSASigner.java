package uk.gov.di.ipv.core.library.signing;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.crypto.ECDSASigner;
import com.nimbusds.jose.jwk.ECKey;

public class LocalECDSASigner extends ECDSASigner implements CoreSigner {
    private final ECKey ecKey;

    public LocalECDSASigner(ECKey ecKey) throws JOSEException {
        super(ecKey);
        this.ecKey = ecKey;
    }

    @Override
    public String getKid() {
        return ecKey.getKeyID();
    }
}
