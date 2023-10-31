package uk.gov.di.ipv.core.library.domain;

import uk.gov.di.ipv.core.library.annotations.ExcludeFromGeneratedCoverageReport;

import java.util.Set;

@ExcludeFromGeneratedCoverageReport
public class CriConstants {
    private CriConstants() {
        throw new IllegalStateException("Utility class");
    }

    public static final String PASSPORT_CRI = "ukPassport";
    public static final String DRIVING_LICENCE_CRI = "drivingLicence";
    public static final String FRAUD_CRI = "fraud";
    public static final String KBV_CRI = "kbv";
    public static final String ADDRESS_CRI = "address";
    public static final String DCMAW_CRI = "dcmaw";
    public static final String CLAIMED_IDENTITY_CRI = "claimedIdentity";
    public static final String F2F_CRI = "f2f";

    public static final Set<String> NON_EVIDENCE_CRI_TYPES =
            Set.of(ADDRESS_CRI, CLAIMED_IDENTITY_CRI);
    public static final String HMRC_KBV_CRI = "hmrcKbv";
    public static final String NINO_CRI = "nino";
}
