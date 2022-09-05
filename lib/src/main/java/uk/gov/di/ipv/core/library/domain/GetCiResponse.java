package uk.gov.di.ipv.core.library.domain;

import lombok.Data;

import java.util.List;

@Data
public class GetCiResponse {
    private final List<ContraIndicatorItem> contraIndicators;
}
