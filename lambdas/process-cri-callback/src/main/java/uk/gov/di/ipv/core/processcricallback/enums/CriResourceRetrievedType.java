package uk.gov.di.ipv.core.processcricallback.enums;

import lombok.Getter;

@Getter
public enum CriResourceRetrievedType {
    PENDING("pending"),
    VC("vc"),
    EMPTY("empty"),
    ERROR("error");

    private final String type;

    CriResourceRetrievedType(String type) {
        this.type = type;
    }
}
