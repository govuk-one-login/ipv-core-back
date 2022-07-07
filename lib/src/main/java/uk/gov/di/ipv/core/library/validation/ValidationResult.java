package uk.gov.di.ipv.core.library.validation;

import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.Setter;

@Getter
@Setter
@AllArgsConstructor
public class ValidationResult {
    private final boolean valid;

    public static ValidationResult createValidResult() {
        return new ValidationResult(true);
    }
}
