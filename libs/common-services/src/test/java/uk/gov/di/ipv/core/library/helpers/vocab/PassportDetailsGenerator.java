package uk.gov.di.ipv.core.library.helpers.vocab;

import uk.gov.di.model.PassportDetails;

public class PassportDetailsGenerator {
    private PassportDetailsGenerator() {}

    public static PassportDetails createPassportDetails(
            String documentNumber, String icaoIssuerCode, String expiryDate) {
        PassportDetails passportDetails = new PassportDetails();
        passportDetails.setDocumentNumber(documentNumber);
        passportDetails.setIcaoIssuerCode(icaoIssuerCode);
        passportDetails.setExpiryDate(expiryDate);
        return passportDetails;
    }
}
