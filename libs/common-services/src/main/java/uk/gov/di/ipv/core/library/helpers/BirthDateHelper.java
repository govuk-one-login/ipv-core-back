package uk.gov.di.ipv.core.library.helpers;

import uk.gov.di.model.BirthDate;

public class BirthDateHelper {
    public static BirthDate createBirthDate(String value) {
        var birthDate = new BirthDate();
        birthDate.setValue(value);
        return birthDate;
    }
}
