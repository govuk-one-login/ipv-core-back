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
        var drivingPermit = new DrivingPermitDetails();
        drivingPermit.setPersonalNumber(personalNumber);
        drivingPermit.setExpiryDate(expiryDate);
        drivingPermit.setIssuedBy(issuedBy);
        drivingPermit.setIssueDate(issueDate);
        drivingPermit.setIssueNumber(issueNumber);
        return drivingPermit;
    }

    public static DrivingPermitDetails createDrivingPermitDetails(
            String personalNumber, String expiryDate, String issuedBy, String issueDate) {
        var drivingPermit = new DrivingPermitDetails();
        drivingPermit.setPersonalNumber(personalNumber);
        drivingPermit.setExpiryDate(expiryDate);
        drivingPermit.setIssuedBy(issuedBy);
        drivingPermit.setIssueDate(issueDate);
        return drivingPermit;
    }
}
