package uk.gov.di.ipv.core.library.dto;

import com.fasterxml.jackson.annotation.JsonProperty;
import lombok.Data;

import java.util.List;

@Data
public class ContraIndicatorDto {
    private String code;
    private String issuanceDate;
    private String document;

    @JsonProperty("txn")
    private List<String> txns;

    @JsonProperty("mitigation")
    private List<ContraIndicatorMitigationDto> completeMitigations;

    @JsonProperty("incompleteMitigation")
    private List<ContraIndicatorMitigationDto> incompleteMitigations;
}
