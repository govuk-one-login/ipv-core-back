package uk.gov.di.ipv.domain.gpg45;

import com.fasterxml.jackson.annotation.JsonEnumDefaultValue;
import com.fasterxml.jackson.annotation.JsonValue;

public enum Score {

    @JsonEnumDefaultValue
    NOT_AVAILABLE(0),
    ONE(1),
    TWO(2),
    THREE(3),
    FOUR(4);

    private final int score;

    Score(final int score) {
        this.score = score;
    }

    @JsonValue
    public int getScoreValue() {
        return score;
    }
}
