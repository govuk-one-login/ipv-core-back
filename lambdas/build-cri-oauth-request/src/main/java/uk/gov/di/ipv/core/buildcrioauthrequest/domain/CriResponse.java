package uk.gov.di.ipv.core.buildcrioauthrequest.domain;

import com.fasterxml.jackson.annotation.JsonCreator;
import com.fasterxml.jackson.annotation.JsonProperty;
import lombok.Getter;
import uk.gov.di.ipv.core.library.domain.BaseResponse;

@Getter
public class CriResponse extends BaseResponse {
    @JsonProperty private final CriDetails cri;

    @JsonCreator
    public CriResponse(@JsonProperty(value = "cri", required = true) CriDetails cri) {
        this.cri = cri;
    }
}
