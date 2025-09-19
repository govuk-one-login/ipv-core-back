package uk.gov.di.ipv.core.library.config.domain;

import com.fasterxml.jackson.annotation.JsonIgnore;
import lombok.Builder;
import lombok.Data;
import lombok.NonNull;
import lombok.extern.jackson.Jacksonized;
import uk.gov.di.ipv.core.library.dto.CriConfig;

import java.util.Map;

@Data
@Builder
@Jacksonized
public class CriConnectionWrapper<T extends CriConfig> {
    @NonNull String id;
    @NonNull String name;
    @NonNull String enabled;
    @NonNull String unavailable;
    String allowedSharedAttributes;
    @NonNull String activeConnection;
    @NonNull Map<String, @NonNull T> connections;

    @JsonIgnore
    public T getActiveConfig() {
        return connections.get(activeConnection);
    }
}
