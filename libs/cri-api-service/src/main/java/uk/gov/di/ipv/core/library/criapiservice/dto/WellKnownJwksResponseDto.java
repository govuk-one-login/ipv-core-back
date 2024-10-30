package uk.gov.di.ipv.core.library.criapiservice.dto;

import com.fasterxml.jackson.annotation.JsonProperty;
import com.nimbusds.jose.jwk.JWK;
import lombok.Getter;
import uk.gov.di.ipv.core.library.annotations.ExcludeFromGeneratedCoverageReport;

import java.util.List;

@ExcludeFromGeneratedCoverageReport
@Getter
public class WellKnownJwksResponseDto {
    @JsonProperty(value = "keys")
    private List<JWK> keys;
}
