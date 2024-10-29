package uk.gov.di.ipv.core.reconcilemigratedvcs.domain;

import com.fasterxml.jackson.annotation.JsonIgnore;
import com.nimbusds.jose.JWSVerifier;
import lombok.AllArgsConstructor;
import lombok.Getter;

import java.util.concurrent.atomic.AtomicInteger;

@Getter
@AllArgsConstructor
public class VerifierAndUseCount {
    @JsonIgnore private final JWSVerifier verifier;
    private final String publicKey;
    private final AtomicInteger useCount;
}
