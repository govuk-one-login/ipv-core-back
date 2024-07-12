package uk.gov.di.ipv.core.library.helpers.vocab;

import uk.gov.di.model.ResidencePermitDetails;

public class ResidencePermitDetailsGenerator {
    private ResidencePermitDetailsGenerator() {}

    public static ResidencePermitDetails createResidencePermitDetails(
            String documentNumber, String expiryDate, String documentType, String icaoIssuerCode) {
        var residencePermitDetails = new ResidencePermitDetails();
        residencePermitDetails.setDocumentNumber(documentNumber);
        residencePermitDetails.setExpiryDate(expiryDate);
        residencePermitDetails.setDocumentType(documentType);
        residencePermitDetails.setIcaoIssuerCode(icaoIssuerCode);

        return residencePermitDetails;
    }
}
