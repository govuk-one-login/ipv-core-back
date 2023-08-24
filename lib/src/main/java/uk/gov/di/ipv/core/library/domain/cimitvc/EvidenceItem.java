package uk.gov.di.ipv.core.library.domain.cimitvc;

import lombok.Getter;

import java.util.List;

@Getter
public class EvidenceItem {
    private String type;
    private List<ContraIndicator> contraIndicator;
}
