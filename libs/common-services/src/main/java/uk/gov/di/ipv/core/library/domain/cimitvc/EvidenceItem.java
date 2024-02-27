package uk.gov.di.ipv.core.library.domain.cimitvc;

import com.fasterxml.jackson.databind.annotation.JsonDeserialize;
import lombok.Data;
import lombok.Getter;
import uk.gov.di.ipv.core.library.annotations.ExcludeFromGeneratedCoverageReport;

import java.util.List;

@ExcludeFromGeneratedCoverageReport
@Getter
@Data
@JsonDeserialize(using = EvidenceItemDeserializer.class)
public class EvidenceItem {
    private final String type;
    private final List<String> txn;
    private final List<ContraIndicator> contraIndicator;
}
