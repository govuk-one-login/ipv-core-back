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

    @JsonProperty private String sub;

    @JsonProperty private String vot;

    @JsonProperty private String vtm;

    @JsonCreator
    public UserIdentity(
            @JsonProperty(
                            value = "https://vocab.sign-in.service.gov.uk/v1/credentials",
                            required = true)
                    List<String> vcs,
            @JsonProperty(value = "sub", required = true) String sub,
            @JsonProperty(value = "vot", required = true) String vot,
            @JsonProperty(value = "vtm", required = true) String vtm) {
        this.vcs = vcs;
        this.sub = sub;
        this.vot = vot;
        this.vtm = vtm;
    }

    public static class Builder {
        private List<String> vcs;
        private String sub;
        private String vot;
        private String vtm;

        public Builder setVcs(List<String> vcs) {
            this.vcs = vcs;
            return this;
        }

        public Builder setSub(String sub) {
            this.sub = sub;
            return this;
        }

        public Builder setVot(String vot) {
            this.vot = vot;
            return this;
        }

        public Builder setVtm(String vtm) {
            this.vtm = vtm;
            return this;
        }

        public UserIdentity build() {
            return new UserIdentity(vcs, sub, vot, vtm);
        }
    }
}
