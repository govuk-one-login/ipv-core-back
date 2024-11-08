package uk.gov.di.ipv.core.library.signing;

import com.nimbusds.jose.JWSSigner;

public interface CoreSigner extends JWSSigner {
    String getKid();
}
