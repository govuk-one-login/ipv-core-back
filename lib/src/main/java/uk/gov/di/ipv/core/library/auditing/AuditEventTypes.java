package uk.gov.di.ipv.core.library.auditing;

import uk.gov.di.ipv.core.library.annotations.ExcludeFromGeneratedCoverageReport;

@ExcludeFromGeneratedCoverageReport
public enum AuditEventTypes {
    IPV_CRI_ACCESS_TOKEN_EXCHANGED,
    IPV_CRI_AUTH_RESPONSE_RECEIVED,
    IPV_GPG45_PROFILE_MATCHED,
    IPV_IDENTITY_REUSE_COMPLETE,
    IPV_IDENTITY_REUSE_RESET,
    IPV_IDENTITY_ISSUED,
    IPV_JOURNEY_END,
    IPV_JOURNEY_START,
    IPV_REDIRECT_TO_CRI,
    IPV_VC_RECEIVED,
    IPV_F2F_CRI_VC_RECEIVED,
    IPV_F2F_CRI_VC_CONSUMED,
    IPV_F2F_CRI_VC_ERROR
}
