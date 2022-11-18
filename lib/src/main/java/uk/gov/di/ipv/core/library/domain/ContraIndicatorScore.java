package uk.gov.di.ipv.core.library.domain;

import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.NoArgsConstructor;

import java.util.List;

@Getter
@AllArgsConstructor
@NoArgsConstructor
public class ContraIndicatorScore {
    private String ci;
    private Integer detectedScore;
    private Integer checkedScore;
    private String fidCode;
    private List<String> mitigations;
}
