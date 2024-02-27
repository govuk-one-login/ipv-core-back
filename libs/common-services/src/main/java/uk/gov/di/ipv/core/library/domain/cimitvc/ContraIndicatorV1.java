package uk.gov.di.ipv.core.library.domain.cimitvc;

import lombok.Builder;
import lombok.EqualsAndHashCode;
import lombok.Getter;
import lombok.ToString;

import java.util.List;

@Getter
@Builder
@ToString
@EqualsAndHashCode
public class ContraIndicatorV1 implements ContraIndicator {
    private final String code;
    private final List<String> issuers;
    private final String issuanceDate;
    private final String document;
    private final List<String> txn;
    private final List<Mitigation> mitigation;
    private final List<Mitigation> incompleteMitigation;

    public boolean isMitigated() {
        return mitigation != null && !mitigation.isEmpty();
    }
}
