package uk.gov.di.ipv.core.library.cimit.domain;

import lombok.Data;
import uk.gov.di.ipv.core.library.domain.ContraIndicatorItem;

import java.util.List;

@Data
public class GetCiResponse {
    private final List<ContraIndicatorItem> contraIndicators;
}
