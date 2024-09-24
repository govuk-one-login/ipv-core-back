export interface IpvSessionDetails {
  subject: string;
  journeyId: string;
  journeyType: string;
  isReproveIdentity: boolean;
  inheritedIdentity?: {
    inheritedIdentityId?: string;
    errorJwt?: boolean;
  };
  redirectUrl?: string;
}
