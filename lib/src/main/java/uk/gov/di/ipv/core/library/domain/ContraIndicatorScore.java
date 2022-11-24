package uk.gov.di.ipv.core.library.domain;

import lombok.Getter;

import java.util.List;

@Getter
public class ContraIndicatorScore {
    private String ci;
    private Integer detectedScore;
    private Integer checkedScore;
    private String fidCode;
    private List<String> mitigations;

    public ContraIndicatorScore() {}

    public ContraIndicatorScore(
            String ci,
            int detectedScore,
            int checkedScore,
            String fidCode,
            List<String> mitigations) {
        this.ci = ci;
        this.detectedScore = detectedScore;
        this.checkedScore = checkedScore;
        this.fidCode = fidCode;
        this.mitigations = mitigations;
    }
}
