package uk.gov.di.ipv.domain.gpg45;

import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@NoArgsConstructor
@AllArgsConstructor
public class EvidenceScore {

    private Score strength = Score.NOT_AVAILABLE;
    private Score validity = Score.NOT_AVAILABLE;

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;

        EvidenceScore that = (EvidenceScore) o;
        return this.hashCode() == that.hashCode();
    }

    @Override
    public int hashCode() {
        return System.identityHashCode(this);
    }
}
