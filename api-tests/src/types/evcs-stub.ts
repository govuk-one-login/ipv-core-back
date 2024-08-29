export type EvcsStubPostVcsRequest = EvcsStubPostVcsCredential[];

export interface EvcsStubPostVcsCredential {
  vc: string;
  state: "CURRENT" | "PENDING" | "PENDING_RETURN" | "VERIFICATION";
  metadata: object;
  provenance: "ONLINE" | "OFFLINE" | "EXTERNAL" | "MIGRATED" | "OTHER";
}
