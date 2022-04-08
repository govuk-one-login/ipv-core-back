package uk.gov.di.ipv.core.library.domain;

import com.fasterxml.jackson.annotation.JsonCreator;
import com.fasterxml.jackson.annotation.JsonProperty;
import lombok.Getter;
import lombok.Setter;
import uk.gov.di.ipv.core.library.annotations.ExcludeFromGeneratedCoverageReport;

import java.util.List;

@Getter
@Setter
@ExcludeFromGeneratedCoverageReport
public class UserIdentity {
    @JsonProperty private List<String> vcs;

    @JsonCreator
    public UserIdentity(@JsonProperty(value = "vcs", required = true) List<String> vcs) {
        this.vcs = vcs;
    }
}
