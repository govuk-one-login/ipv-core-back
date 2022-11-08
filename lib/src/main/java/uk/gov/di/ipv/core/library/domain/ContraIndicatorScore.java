package uk.gov.di.ipv.core.library.domain;

import lombok.Getter;

@Getter
public class ContraIndicatorScore {
    private String ci;
    private Integer detectedScore;
    private Integer checkedScore;
    private String fidCode;

    public ContraIndicatorScore() {}

    public ContraIndicatorScore(String ci, int detectedScore, int checkedScore, String fidCode) {
        this.ci = ci;
        this.detectedScore = detectedScore;
        this.checkedScore = checkedScore;
        this.fidCode = fidCode;
    }
}
