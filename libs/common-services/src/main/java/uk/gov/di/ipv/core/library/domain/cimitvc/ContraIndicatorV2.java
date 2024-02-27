package uk.gov.di.ipv.core.library.domain.cimitvc;

import lombok.Builder;

import java.util.List;

@Builder
public record ContraIndicatorV2(
        String code,
        List<String> issuers,
        String issuanceDate,
        List<String> document,
        List<String> txn,
        List<Mitigation> mitigation,
        List<Mitigation> incompleteMitigation)
        implements ContraIndicator {

    public boolean isMitigated() {
        return mitigation != null && !mitigation.isEmpty();
    }

    @Override
    public List<String> getIssuers() {
        return issuers;
    }

    @Override
    public String getCode() {
        return code;
    }

    @Override
    public String getIssuanceDate() {
        return issuanceDate;
    }
}
