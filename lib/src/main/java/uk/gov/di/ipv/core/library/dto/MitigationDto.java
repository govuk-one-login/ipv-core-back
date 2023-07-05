package uk.gov.di.ipv.core.library.dto;

import com.fasterxml.jackson.annotation.JsonProperty;
import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;
import uk.gov.di.ipv.core.library.annotations.ExcludeFromGeneratedCoverageReport;

import java.util.List;

@ExcludeFromGeneratedCoverageReport
@Data
@NoArgsConstructor
@AllArgsConstructor
public class MitigationDto {
    private String code;

    @JsonProperty("id")
    private List<MitigationCredentialDto> mitigatingCredential;
}
