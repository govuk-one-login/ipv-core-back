package uk.gov.di.ipv.core.library.auditing;

import uk.gov.di.ipv.core.library.annotations.ExcludeFromGeneratedCoverageReport;

@ExcludeFromGeneratedCoverageReport
public enum AuditEventTypes {
    IPV_ACCOUNT_INTERVENTION_END,
    IPV_ACCOUNT_INTERVENTION_START,
    IPV_ASYNC_CRI_VC_RECEIVED,
    IPV_ASYNC_CRI_VC_CONSUMED,
    IPV_ASYNC_CRI_VC_ERROR,
    IPV_CONTINUITY_OF_IDENTITY_CHECK_END,
    IPV_CONTINUITY_OF_IDENTITY_CHECK_START,
    IPV_CORE_CRI_RESOURCE_RETRIEVED,
    IPV_CORE_VC_RESET,
    IPV_CRI_ACCESS_TOKEN_EXCHANGED,
    IPV_CRI_AUTH_RESPONSE_RECEIVED,
    IPV_DWP_KBV_CRI_ABANDONED,
    IPV_DWP_KBV_CRI_START,
    IPV_DWP_KBV_CRI_THIN_FILE_ENCOUNTERED,
    IPV_DWP_KBV_CRI_VC_ISSUED,
    IPV_F2F_CORRELATION_FAIL,
    IPV_F2F_CRI_VC_CONSUMED,
    IPV_F2F_CRI_VC_ERROR,
    IPV_F2F_CRI_VC_RECEIVED,
    IPV_F2F_PROFILE_NOT_MET_FAIL,
    IPV_F2F_USER_CANCEL_END,
    IPV_F2F_USER_CANCEL_START,
    IPV_GPG45_PROFILE_MATCHED,
    IPV_IDENTITY_ISSUED,
    IPV_IDENTITY_REUSE_COMPLETE,
    IPV_IDENTITY_REUSE_RESET,
    IPV_IDENTITY_STORED,
    IPV_INHERITED_IDENTITY_VC_RECEIVED,
    IPV_JOURNEY_END,
    IPV_JOURNEY_START,
    IPV_MITIGATION_START,
    IPV_NO_PHOTO_ID_JOURNEY_START,
    IPV_REDIRECT_TO_CRI,
    IPV_SUBJOURNEY_START,
    IPV_USER_DETAILS_UPDATE_ABORTED,
    IPV_USER_DETAILS_UPDATE_END,
    IPV_USER_DETAILS_UPDATE_SELECTED,
    IPV_USER_DETAILS_UPDATE_START,
    IPV_VC_RECEIVED,
    IPV_VCS_MIGRATED,
    IPV_EVCS_MIGRATION_SUCCESS,
    IPV_EVCS_MIGRATION_SKIPPED,
    IPV_EVCS_MIGRATION_FAILURE,
    IPV_APP_HANDOFF_START,
    IPV_APP_MISSING_CONTEXT,
    IPV_APP_SESSION_RECOVERED,
    IPV_INTERNATIONAL_ADDRESS_START,
    IPV_REVERIFY_START,
    IPV_REVERIFY_END
}
