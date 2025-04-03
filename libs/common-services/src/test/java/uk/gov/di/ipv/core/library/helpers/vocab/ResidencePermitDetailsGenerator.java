package uk.gov.di.ipv.core.library.helpers.vocab;

import uk.gov.di.model.ResidencePermitDetails;

public class ResidencePermitDetailsGenerator {
    private ResidencePermitDetailsGenerator() {}

    public static ResidencePermitDetails createResidencePermitDetails(
            String documentNumber, String expiryDate, String documentType, String icaoIssuerCode) {
        return ResidencePermitDetails.builder()
                .withDocumentNumber(documentNumber)
                .withExpiryDate(expiryDate)
                .withDocumentType(documentType)
                .withIcaoIssuerCode(icaoIssuerCode)
                .build();
    }
}
