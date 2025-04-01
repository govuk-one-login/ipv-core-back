package uk.gov.di.ipv.core.library.helpers.vocab;

import uk.gov.di.model.BankAccountDetails;

public class BankAccountGenerator {
    private BankAccountGenerator() {}

    public static BankAccountDetails createBankAccountDetails(
            String accountNumber, String sortCode, String validFrom, String validUntil) {
        return BankAccountDetails.builder()
                .withAccountNumber(accountNumber)
                .withSortCode(sortCode)
                .withValidFrom(validFrom)
                .withValidUntil(validUntil)
                .build();
    }
}
