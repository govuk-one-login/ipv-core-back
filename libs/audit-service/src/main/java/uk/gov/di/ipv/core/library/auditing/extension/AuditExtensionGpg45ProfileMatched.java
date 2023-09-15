package uk.gov.di.ipv.core.library.auditing.extension;

import uk.gov.di.ipv.core.library.domain.gpg45.Gpg45Profile;
import uk.gov.di.ipv.core.library.domain.gpg45.Gpg45Scores;

import java.util.List;

public class AuditExtensionGpg45ProfileMatched implements AuditExtensions {
    private final Gpg45Profile gpg45Profile;
    private final Gpg45Scores gpg45Scores;
    private final List<String> vcTxnIds;

    public AuditExtensionGpg45ProfileMatched(
            Gpg45Profile gpg45Profile, Gpg45Scores gpg45Scores, List<String> vcTxnIds) {
        this.gpg45Profile = gpg45Profile;
        this.gpg45Scores = gpg45Scores;
        this.vcTxnIds = vcTxnIds;
    }

    public Gpg45Profile getGpg45Profile() {
        return gpg45Profile;
    }

    public Gpg45Scores getGpg45Scores() {
        return gpg45Scores;
    }

    public List<String> getVcTxnIds() {
        return vcTxnIds;
    }
}
