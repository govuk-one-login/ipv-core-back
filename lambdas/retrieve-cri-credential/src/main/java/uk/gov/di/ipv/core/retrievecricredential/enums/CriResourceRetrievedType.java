package uk.gov.di.ipv.core.retrievecricredential.enums;

import lombok.Getter;

@Getter
public enum CriResourceRetrievedType {
    PENDING("pending"),
    VC("vc"),
    ERROR("error");

    private final String type;

    CriResourceRetrievedType(String type) {
        this.type = type;
    }
}
