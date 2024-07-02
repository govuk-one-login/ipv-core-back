package uk.gov.di.ipv.core.library.dto;

import com.fasterxml.jackson.annotation.JsonProperty;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;
import uk.gov.di.ipv.core.library.annotations.ExcludeFromGeneratedCoverageReport;
import uk.gov.di.ipv.core.library.domain.Cri;

import java.util.List;

@ExcludeFromGeneratedCoverageReport
@NoArgsConstructor
@AllArgsConstructor
@Data
@Builder
public class CriCallbackRequest {
    private String authorizationCode;

    @JsonProperty("credentialIssuerId")
    private Cri credentialIssuer;

    private String ipvSessionId;
    private String redirectUri;
    private String state;
    private String error;
    private String errorDescription;
    private String ipAddress;
    private String deviceInformation;
    private List<String> featureSet;
}
