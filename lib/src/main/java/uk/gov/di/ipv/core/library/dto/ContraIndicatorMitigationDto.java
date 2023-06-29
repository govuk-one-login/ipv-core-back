package uk.gov.di.ipv.core.library.dto;

import com.fasterxml.jackson.annotation.JsonProperty;
import lombok.Data;

import java.util.List;

@Data
public class ContraIndicatorMitigationDto {
    private String code;

    @JsonProperty("mitigatingCredential")
    private List<ContraIndicatorMitigatingCredentialDto> mitigatingCredentials;
}
