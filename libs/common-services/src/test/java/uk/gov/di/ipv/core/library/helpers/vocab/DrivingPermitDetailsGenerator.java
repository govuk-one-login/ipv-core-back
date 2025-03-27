package uk.gov.di.ipv.core.library.helpers.vocab;

import uk.gov.di.model.DrivingPermitDetails;

public class DrivingPermitDetailsGenerator {
    private DrivingPermitDetailsGenerator() {}

    public static DrivingPermitDetails createDrivingPermitDetails(
            String personalNumber,
            String expiryDate,
            String issuedBy,
            String issueDate,
            String issueNumber) {
        return DrivingPermitDetails.builder()
                .withPersonalNumber(personalNumber)
                .withExpiryDate(expiryDate)
                .withIssuedBy(issuedBy)
                .withIssueDate(issueDate)
                .withIssueNumber(issueNumber)
                .build();
    }

    public static DrivingPermitDetails createDrivingPermitDetails(
            String personalNumber, String expiryDate, String issuedBy, String issueDate) {
        return DrivingPermitDetails.builder()
                .withPersonalNumber(personalNumber)
                .withExpiryDate(expiryDate)
                .withIssuedBy(issuedBy)
                .withIssueDate(issueDate)
                .build();
    }
}
