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
    @JsonProperty("https://vocab.sign-in.service.gov.uk/v1/credentials")
    private List<String> vcs;

    @JsonProperty private String vot;

    @JsonCreator
    public UserIdentity(
            @JsonProperty(
                            value = "https://vocab.sign-in.service.gov.uk/v1/credentials",
                            required = true)
                    List<String> vcs,
            @JsonProperty(value = "vot", required = true) String vot) {
        this.vcs = vcs;
        this.vot = vot;
    }

    public static class Builder {
        private List<String> vcs;
        private String vot;

        public Builder setVcs(List<String> vcs) {
            this.vcs = vcs;
            return this;
        }

        public Builder setVot(String vot) {
            this.vot = vot;
            return this;
        }

        public UserIdentity build() {
            return new UserIdentity(vcs, vot);
        }
    }
}
