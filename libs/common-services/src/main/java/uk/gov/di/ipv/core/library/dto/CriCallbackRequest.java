package uk.gov.di.ipv.core.library.dto;

import com.fasterxml.jackson.annotation.JsonIgnore;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;
import software.amazon.awssdk.utils.StringUtils;
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
    private String credentialIssuerId;
    private String ipvSessionId;
    private String redirectUri;
    private String state;
    private String error;
    private String errorDescription;
    private String ipAddress;
    private String deviceInformation;
    private List<String> featureSet;

    @JsonIgnore
    public Cri getCredentialIssuer() {
        if (StringUtils.isEmpty(credentialIssuerId)) {
            return null;
        }
        return Cri.fromId(credentialIssuerId);
    }
}
