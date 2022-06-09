package uk.gov.di.ipv.core.credentialissuer.domain;

import com.fasterxml.jackson.annotation.JsonCreator;
import com.fasterxml.jackson.annotation.JsonProperty;
import lombok.Getter;

@Getter
public class CriResponse {
    @JsonProperty private final CriDetails cri;

    @JsonCreator
    public CriResponse(@JsonProperty(value = "cri", required = true) CriDetails cri) {
        this.cri = cri;
    }
}
