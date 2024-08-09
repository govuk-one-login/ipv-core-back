package uk.gov.di.ipv.core.library.helpers.vocab;

import uk.gov.di.model.BankAccountDetails;

public class BankAccountGenerator {
    private BankAccountGenerator() {}

    public static BankAccountDetails createBankAccountDetails(
            String accountNumber, String sortCode, String validFrom, String validUntil) {
        var bankAccountDetails = new BankAccountDetails();
        bankAccountDetails.setAccountNumber(accountNumber);
        bankAccountDetails.setSortCode(sortCode);
        bankAccountDetails.setValidFrom(validFrom);
        bankAccountDetails.setValidUntil(validUntil);
        return bankAccountDetails;
    }
}
