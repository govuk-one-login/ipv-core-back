package uk.gov.di.ipv.core.library.helpers.vocab;

import uk.gov.di.model.IdCardDetails;

public class IdCardDetailsGenerator {
    private IdCardDetailsGenerator() {}

    public static IdCardDetails createIdCardDetails(
            String documentNumber, String expiryDate, String icaoIssuerCode, String issueDate) {
        return IdCardDetails.builder()
                .withDocumentNumber(documentNumber)
                .withExpiryDate(expiryDate)
                .withIcaoIssuerCode(icaoIssuerCode)
                .withIssueDate(issueDate)
                .build();
    }
}
