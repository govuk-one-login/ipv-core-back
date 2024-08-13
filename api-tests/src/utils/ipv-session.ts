export class IPVSessionDetails {
  subject: string;
  journeyId: string;
  journeyType: string;
  isReproveIdentity: boolean;
  inheritedIdentityId: string;

  constructor(
    subject: string,
    journeyId: string,
    journeyType: string,
    isReproveIdentity: boolean,
    inheritedIdentityId: string,
  ) {
    this.subject = subject;
    this.journeyId = journeyId;
    this.journeyType = journeyType;
    this.isReproveIdentity = isReproveIdentity;
    this.inheritedIdentityId = inheritedIdentityId;
  }
}
