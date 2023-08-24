package uk.gov.di.ipv.core.library.domain.cimitvc;

import lombok.Getter;

import java.util.List;

@Getter
public class CiMitVc {
    private List<String> type;
    private List<EvidenceItem> evidence;
}
