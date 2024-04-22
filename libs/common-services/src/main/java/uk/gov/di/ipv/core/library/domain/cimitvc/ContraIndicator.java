package uk.gov.di.ipv.core.library.domain.cimitvc;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.ToString;

import java.util.List;

@AllArgsConstructor
@NoArgsConstructor(force = true)
@Getter
@Builder
@ToString
public class ContraIndicator {
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
