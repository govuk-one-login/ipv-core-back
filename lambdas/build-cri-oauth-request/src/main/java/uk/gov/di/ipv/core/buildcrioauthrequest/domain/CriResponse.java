package uk.gov.di.ipv.core.buildcrioauthrequest.domain;

import com.fasterxml.jackson.annotation.JsonCreator;
import com.fasterxml.jackson.annotation.JsonProperty;
import lombok.EqualsAndHashCode;
import lombok.Getter;
import uk.gov.di.ipv.core.library.domain.JourneyResponse;

@Getter
@EqualsAndHashCode(callSuper = true)
public class CriResponse extends JourneyResponse {
    @JsonProperty private final CriDetails cri;

    @JsonCreator
    public CriResponse(
            @JsonProperty(value = "journey", required = true) String journey,
            @JsonProperty(value = "cri", required = true) CriDetails cri) {
        super(journey);
        this.cri = cri;
    }
}
