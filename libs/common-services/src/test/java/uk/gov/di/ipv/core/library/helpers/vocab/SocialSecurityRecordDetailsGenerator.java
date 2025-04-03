package uk.gov.di.ipv.core.library.helpers.vocab;

import uk.gov.di.model.SocialSecurityRecordDetails;

public class SocialSecurityRecordDetailsGenerator {
    private SocialSecurityRecordDetailsGenerator() {}

    public static SocialSecurityRecordDetails createSocialSecurityRecordDetails(
            String personalNumber) {
        return SocialSecurityRecordDetails.builder().withPersonalNumber(personalNumber).build();
    }
}
