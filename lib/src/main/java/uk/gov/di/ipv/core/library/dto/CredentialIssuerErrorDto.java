package uk.gov.di.ipv.core.library.dto;

import lombok.AllArgsConstructor;
import lombok.Getter;
import uk.gov.di.ipv.core.library.annotations.ExcludeFromGeneratedCoverageReport;

@ExcludeFromGeneratedCoverageReport
@Getter
@AllArgsConstructor
public class CredentialIssuerErrorDto {
    private final String error;
    private final String errorDescription;
    private final String state;
    private final String credentialIssuerId;
    private final String ipvSessionId;
    private final String redirectUri;
}
