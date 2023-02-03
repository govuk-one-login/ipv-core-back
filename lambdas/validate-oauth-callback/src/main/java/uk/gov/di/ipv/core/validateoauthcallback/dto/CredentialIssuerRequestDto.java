package uk.gov.di.ipv.core.validateoauthcallback.dto;

import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;
import uk.gov.di.ipv.core.library.annotations.ExcludeFromGeneratedCoverageReport;

@ExcludeFromGeneratedCoverageReport
@NoArgsConstructor
@AllArgsConstructor
@Data
public class CredentialIssuerRequestDto {
    private String authorizationCode;
    private String credentialIssuerId;
    private String ipvSessionId;
    private String redirectUri;
    private String state;
    private String error;
    private String errorDescription;
    private String ipAddress;
}
