package uk.gov.di.ipv.core.library.domain.cimitvc;

import java.util.List;

public interface ContraIndicator {
    String getCode();

    String getIssuanceDate();

    boolean isMitigated();

    List<String> getIssuers();
}
