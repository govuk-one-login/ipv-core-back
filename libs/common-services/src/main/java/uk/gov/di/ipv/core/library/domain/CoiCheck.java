package uk.gov.di.ipv.core.library.domain;

import uk.gov.di.ipv.core.library.enums.CoiCheckType;

public record CoiCheck(boolean isSuccessful, CoiCheckType type) {}
