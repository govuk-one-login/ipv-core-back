package uk.gov.di.ipv.core.library.domain;

import lombok.Getter;
import uk.gov.di.ipv.core.library.annotations.ExcludeFromGeneratedCoverageReport;

import java.util.Arrays;
import java.util.List;

@Getter
@ExcludeFromGeneratedCoverageReport
public enum CriIdentifer {
    PASSPORT("ukPassport"),
    DRIVING_LICENCE("drivingLicence"),
    EXPERIAN_FRAUD("fraud"),
    EXPERIAN_KBV("kbv"),
    ADDRESS("address", false, true),
    DCMAW("dcmaw"),
    CLAIMED_IDENTITY("claimedIdentity", false, true),
    F2F("f2f"),
    NINO("nino"),
    TICF("ticf"),
    HMRC_MIGRATION("hmrcMigration", true, false),
    HMRC_KBV("hmrcKbv"),
    BAV("bav");

    private final String id;
    private final boolean isOperationalCri;
    private final boolean isNonEvidenceCri;

    CriIdentifer(String id) {
        this(id, false, false);
    }

    CriIdentifer(String id, boolean isOperational, boolean isNonEvidence) {
        this.id = id;
        this.isOperationalCri = isOperational;
        this.isNonEvidenceCri = isNonEvidence;
    }

    public static final List<String> getOperationalCriIds() {
        return Arrays.stream(CriIdentifer.values())
                .filter(criId -> criId.isOperationalCri())
                .map(CriIdentifer::getId)
                .toList();
    }

    public static final List<String> getNonEvidenceCriIds() {
        return Arrays.stream(CriIdentifer.values())
                .filter(criId -> criId.isNonEvidenceCri())
                .map(CriIdentifer::getId)
                .toList();
    }
}
