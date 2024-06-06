package uk.gov.di.ipv.core.library.auditing;

import uk.gov.di.ipv.core.library.annotations.ExcludeFromGeneratedCoverageReport;

@ExcludeFromGeneratedCoverageReport
public enum AuditEventTypes {
    IPV_CONTINUITY_OF_IDENTITY_CHECK_END,
    IPV_CONTINUITY_OF_IDENTITY_CHECK_START,
    IPV_CORE_CRI_RESOURCE_RETRIEVED,
    IPV_CORE_VC_RESET,
    IPV_CRI_ACCESS_TOKEN_EXCHANGED,
    IPV_CRI_AUTH_RESPONSE_RECEIVED,
    IPV_F2F_CORRELATION_FAIL,
    IPV_F2F_CRI_VC_CONSUMED,
    IPV_F2F_CRI_VC_ERROR,
    IPV_F2F_CRI_VC_RECEIVED,
    IPV_F2F_PROFILE_NOT_MET_FAIL,
    IPV_GPG45_PROFILE_MATCHED,
    IPV_IDENTITY_ISSUED,
    IPV_IDENTITY_REUSE_COMPLETE,
    IPV_IDENTITY_REUSE_RESET,
    IPV_IDENTITY_STORED,
    IPV_INHERITED_IDENTITY_VC_RECEIVED,
    IPV_JOURNEY_END,
    IPV_JOURNEY_START,
    IPV_MITIGATION_START,
    IPV_REDIRECT_TO_CRI,
    IPV_SUBJOURNEY_START,
    IPV_VC_RECEIVED,
    IPV_VC_RESTORED,
    IPV_VC_REVOKED,
    IPV_VC_REVOKED_FAILURE,
}
