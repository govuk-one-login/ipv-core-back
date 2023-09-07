package uk.gov.di.ipv.core.library.validation;

import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.Setter;
import uk.gov.di.ipv.core.library.annotations.ExcludeFromGeneratedCoverageReport;

@ExcludeFromGeneratedCoverageReport
@Getter
@Setter
@AllArgsConstructor
public class ValidationResult<T> {
    private final boolean valid;
    private final T error;

    public static <U> ValidationResult<U> createValidResult() {
        return new ValidationResult<>(true, null);
    }
}
