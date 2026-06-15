package uk.gov.di.ipv.core.library.enums;

public enum IdentityResetType {
    /** Deletes all session VCs. */
    ALL,
    /** Deletes only DCMAW VC from session. */
    DCMAW,
    /** Deletes only DCMAW_ASYNC VC from session. */
    DCMAW_ASYNC,
    /** Deletes all session VCs except address. */
    NAME_ONLY_CHANGE,
    /** Deletes address + fraud VCs from session. */
    ADDRESS_ONLY_CHANGE,
    /** Deletes all session VCs, clears pending record and abandons pending identity in EVCS. */
    PENDING_F2F_ALL,
    /** Deletes all session VCs, clears pending record and abandons pending identity in EVCS. */
    PENDING_DCMAW_ASYNC_ALL,
    /** Deletes all session VCs then reinstates existing CURRENT VCs from EVCS into session. */
    REINSTATE
}
