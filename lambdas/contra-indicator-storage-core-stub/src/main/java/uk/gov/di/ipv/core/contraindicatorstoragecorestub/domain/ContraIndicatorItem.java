package uk.gov.di.ipv.core.contraindicatorstoragecorestub.domain;

import com.google.gson.Gson;
import lombok.Getter;
import uk.gov.di.ipv.core.library.annotations.ExcludeFromGeneratedCoverageReport;

@ExcludeFromGeneratedCoverageReport
@Getter
public class ContraIndicatorItem {
    private static final Gson gson = new Gson();

    private String userId;
    private String sortKey;
    private String iss;
    private String recordedAt;
    private String ci;
    private String ttl;

    @Override
    public String toString() {
        return gson.toJson(this);
    }
}
