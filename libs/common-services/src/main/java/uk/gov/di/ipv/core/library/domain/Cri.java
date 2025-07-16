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
    KBV("kbv"),
    EXPERIAN_KBV("experianKbv"),
    F2F("f2f"),
    HMRC_MIGRATION("hmrcMigration", true),
    NINO("nino"),
    PASSPORT("ukPassport"),
    TICF("ticf");

    private final String id;
    private final boolean isOperationalCri;
    private static final Set<Cri> KBV_CRIS = Set.of(DWP_KBV, KBV, EXPERIAN_KBV);

    Cri(String id) {
        this(id, false);
    }

    Cri(String id, boolean isOperational) {
        this.id = id;
        this.isOperationalCri = isOperational;
    }

    public boolean isKbvCri() {
        return KBV_CRIS.contains(this);
    }

    public static Cri fromId(String id) {
        for (var cri : values()) {
            if (cri.getId().equals(id)) {
                return cri;
            }
        }
        throw new IllegalArgumentException("no cri found with ID " + id);
    }
}
