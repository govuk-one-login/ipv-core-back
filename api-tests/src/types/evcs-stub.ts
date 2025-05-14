export type EvcsStubPostVcsRequest = EvcsStubPostVcsCredential[];

export interface EvcsStubPostVcsCredential {
  vc: string;
  state: "CURRENT" | "PENDING" | "PENDING_RETURN" | "VERIFICATION";
  metadata: object;
  provenance: "ONLINE" | "OFFLINE" | "EXTERNAL" | "MIGRATED" | "OTHER";
}

export interface EvcsStoredIdentity {
  userId: string;
  recordType: StoredIdentityRecordtype.GPG45 | StoredIdentityRecordtype.HMRC;
  storedIdentity: string;
  levelOfConfidence: string;
  isValid: boolean;
}

export enum StoredIdentityRecordtype {
  GPG45 = "idrec:gpg45",
  HMRC = "idrec:Inherited:hmrc",
}
