package uk.gov.di.ipv.core.library.domain;

import lombok.Getter;
import uk.gov.di.ipv.core.library.annotations.ExcludeFromGeneratedCoverageReport;

import java.util.Set;

@Getter
@ExcludeFromGeneratedCoverageReport
public enum Cri {
    ADDRESS("address"),
    BAV("bav"),
    CIMIT("cimit"),
    CLAIMED_IDENTITY("claimedIdentity"),
    DCMAW("dcmaw"),
    DCMAW_ASYNC("dcmawAsync"),
    DRIVING_LICENCE("drivingLicence"),
    DWP_KBV("dwpKbv"),
    EXPERIAN_FRAUD("fraud"),
    EXPERIAN_KBV("experianKbv"),
    F2F("f2f"),
    NINO("nino"),
    PASSPORT("ukPassport"),
    HMRC_MIGRATION("hmrcMigration"),
    TICF("ticf");

    private final String id;
    private static final Set<Cri> KBV_CRIS = Set.of(DWP_KBV, EXPERIAN_KBV);
    private static final String EXPERIAN_KBV_REDIRECT_ID = "kbv";

    Cri(String id) {
        this.id = id;
    }

    public boolean isKbvCri() {
        return KBV_CRIS.contains(this);
    }

    public static Cri fromId(String id) {
        if (EXPERIAN_KBV_REDIRECT_ID.equals(id)) {
            return EXPERIAN_KBV;
        }

        for (var cri : values()) {
            if (cri.getId().equals(id)) {
                return cri;
            }
        }
        throw new IllegalArgumentException("no cri found with ID " + id);
    }
}
