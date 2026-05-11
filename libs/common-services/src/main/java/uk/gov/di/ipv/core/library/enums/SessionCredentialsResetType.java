package uk.gov.di.ipv.core.library.enums;

public enum SessionCredentialsResetType {
    ALL,
    ALL_INC_DCMAW_ASYNC_PENDING, // PYIC-8711: Investigate if we can use PENDING_DCMAW_ASYNC_ALL
    DCMAW,
    DCMAW_ASYNC,
    NAME_ONLY_CHANGE,
    ADDRESS_ONLY_CHANGE,
    PENDING_F2F_ALL,
    PENDING_DCMAW_ASYNC_ALL,
    REINSTATE
}
