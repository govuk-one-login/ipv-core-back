package uk.gov.di.ipv.core.library.config.domain;

import lombok.Builder;
import lombok.Data;
import lombok.NonNull;
import lombok.extern.jackson.Jacksonized;

@Data
@Builder
@Jacksonized
public class CoiConfig {
    @NonNull Integer familyNameChars;
    @NonNull Integer givenNameChars;
}
