package uk.gov.di.ipv.core.library.helpers.vocab;

import uk.gov.di.model.SocialSecurityRecordDetails;

public class SocialSecurityRecordDetailsGenerator {
    private SocialSecurityRecordDetailsGenerator() {}

    public static SocialSecurityRecordDetails createSocialSecurityRecordDetails(
            String personalNumber) {
        var socialSecurityRecord = new SocialSecurityRecordDetails();
        socialSecurityRecord.setPersonalNumber(personalNumber);
        return socialSecurityRecord;
    }
}
