package uk.gov.di.ipv.core.library.validation;

import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.Setter;

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
