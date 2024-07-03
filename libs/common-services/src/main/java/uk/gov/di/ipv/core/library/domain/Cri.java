package uk.gov.di.ipv.core.library.domain;

import lombok.Getter;
import uk.gov.di.ipv.core.library.annotations.ExcludeFromGeneratedCoverageReport;

import java.util.Arrays;
import java.util.List;

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
    EXPERIAN_KBV("kbv"),
    F2F("f2f"),
    HMRC_KBV("hmrcKbv"),
    HMRC_MIGRATION("hmrcMigration", true),
    NINO("nino"),
    PASSPORT("ukPassport"),
    TICF("ticf");

    private final String id;
    private final boolean isOperationalCri;

    Cri(String id) {
        this(id, false);
    }

    Cri(String id, boolean isOperational) {
        this.id = id;
        this.isOperationalCri = isOperational;
    }

    public static Cri fromId(String id) {
        for (var cri : values()) {
            if (cri.getId().equals(id)) {
                return cri;
            }
        }
        throw new IllegalArgumentException("no cri found with ID " + id);
    }

    public static List<String> getOperationalCriIds() {
        return Arrays.stream(Cri.values())
                .filter(Cri::isOperationalCri)
                .map(Cri::getId)
                .toList();
    }
}
