package uk.gov.di.ipv.core.library.domain;

import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.NoArgsConstructor;

@Getter
@NoArgsConstructor
@AllArgsConstructor
public class ContraIndicatorConfig {
    private String ci;
    private Integer detectedScore;
    private Integer checkedScore;
    private String exitCode;
}
