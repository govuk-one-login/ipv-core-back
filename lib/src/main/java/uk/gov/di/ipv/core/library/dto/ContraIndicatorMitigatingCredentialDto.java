package uk.gov.di.ipv.core.library.dto;

import com.fasterxml.jackson.annotation.JsonProperty;
import lombok.Data;

@Data
public class ContraIndicatorMitigatingCredentialDto {
    private String issuer;
    private String validFrom;
    private String txn;

    @JsonProperty("id")
    private String userId;
}
