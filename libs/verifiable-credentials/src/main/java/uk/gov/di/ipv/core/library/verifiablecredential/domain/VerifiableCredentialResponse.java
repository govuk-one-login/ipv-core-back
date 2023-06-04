package uk.gov.di.ipv.core.library.verifiablecredential.domain;

import com.nimbusds.jwt.SignedJWT;
import lombok.Builder;
import lombok.Getter;
import uk.gov.di.ipv.core.library.annotations.ExcludeFromGeneratedCoverageReport;

import java.util.List;

@ExcludeFromGeneratedCoverageReport
@Builder
@Getter
public class VerifiableCredentialResponse {
    private String userId;
    private VerifiableCredentialStatus credentialStatus;
    private List<SignedJWT> verifiableCredentials;
}
