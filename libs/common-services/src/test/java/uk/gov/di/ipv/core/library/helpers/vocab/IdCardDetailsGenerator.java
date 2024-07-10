package uk.gov.di.ipv.core.library.helpers.vocab;

import uk.gov.di.model.IdCardDetails;

public class IdCardDetailsGenerator {
    private IdCardDetailsGenerator() {}

    public static IdCardDetails createIdCardDetails(
            String documentNumber, String expiryDate, String icaoIssuerCode, String issueDate) {
        var idCardDetails = new IdCardDetails();
        idCardDetails.setDocumentNumber(documentNumber);
        idCardDetails.setExpiryDate(expiryDate);
        idCardDetails.setIcaoIssuerCode(icaoIssuerCode);
        idCardDetails.setIssueDate(issueDate);

        return idCardDetails;
    }
}
