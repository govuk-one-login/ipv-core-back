package uk.gov.di.ipv.domain.gpg45;

import com.fasterxml.jackson.annotation.JsonCreator;
import com.fasterxml.jackson.annotation.JsonValue;

public enum ConfidenceLevel {

    NONE(0, "None"),
    LOW(1, "Low"),
    MEDIUM(2, "Medium"),
    HIGH(3, "High"),
    VERY_HIGH(4, "VeryHigh");

    private final int levelOfConfidence;
    private final String name;

    ConfidenceLevel(int levelOfConfidence, String name) {
        this.levelOfConfidence = levelOfConfidence;
        this.name = name;
    }

    public int getValue() {
        return levelOfConfidence;
    }

    @Override
    @JsonValue
    public String toString() {
        return name;
    }

    @JsonCreator
    public static ConfidenceLevel fromString(String text) {
        for (ConfidenceLevel confidenceLevel : ConfidenceLevel.values()) {
            if (confidenceLevel.name.equals(text)) {
                return confidenceLevel;
            }
        }
        return null;
    }
}
