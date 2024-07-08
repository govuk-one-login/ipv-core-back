package uk.gov.di.ipv.core.library.helpers.vocab;

import uk.gov.di.model.BirthDate;

public class BirthDateGenerator {
    private BirthDateGenerator() {}

    public static BirthDate createBirthDate(String value) {
        var birthDate = new BirthDate();
        birthDate.setValue(value);
        return birthDate;
    }
}
