export interface EvcsStubPostVcsRequest {
  userId: string;
  govuk_signin_journey_id: string;
  vcs: EvcsStubPostVcsCredential[];
}

export interface EvcsStubPostVcsCredential {
  vc: string;
  state: "CURRENT" | "PENDING" | "PENDING_RETURN" | "VERIFICATION";
  metadata: object;
  provenance: "ONLINE" | "OFFLINE" | "EXTERNAL" | "MIGRATED" | "OTHER";
}

export interface EvcsStoredIdentity {
  userId: string;
  recordType: StoredIdentityRecordtype.GPG45;
  storedIdentity: string;
  levelOfConfidence: string;
  isValid: boolean;
}

export enum StoredIdentityRecordtype {
  GPG45 = "idrec:gpg45",
}
