package uk.gov.di.ipv.validation;

import java.util.Objects;

public class Validator {

    private Validator() {}

    public static boolean isNullBlankOrEmpty(String value) {
        return Objects.isNull(value) || value.isEmpty() || value.isBlank();
    }
}
