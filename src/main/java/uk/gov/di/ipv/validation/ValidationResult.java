package uk.gov.di.ipv.validation;

import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.Setter;
import uk.gov.di.ipv.domain.ErrorResponse;

@Getter
@Setter
@AllArgsConstructor
public class ValidationResult {
    private final boolean valid;
    private final ErrorResponse error;

    public static ValidationResult createValidResult() {
        return new ValidationResult(true, null);
    }
}
