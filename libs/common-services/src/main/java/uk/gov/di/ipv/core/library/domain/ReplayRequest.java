package uk.gov.di.ipv.core.library.domain;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.fasterxml.jackson.annotation.JsonProperty;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.util.List;

@AllArgsConstructor
@NoArgsConstructor
@Data
@Builder
@JsonIgnoreProperties(ignoreUnknown = true)
public class ReplayRequest {
    @JsonProperty("Items")
    private List<ReplayItem> items;

    @JsonProperty("Count")
    private Integer count;

    @JsonProperty("ScannedCount")
    private Integer scannedCount;
}
