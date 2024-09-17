package uk.gov.di.ipv.core.buildcrioauthrequest.domain;

import com.fasterxml.jackson.annotation.JsonInclude;
import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.EqualsAndHashCode;
import lombok.NoArgsConstructor;
import uk.gov.di.ipv.core.library.domain.BaseClaim;
import uk.gov.di.model.BirthDate;
import uk.gov.di.model.Name;
import uk.gov.di.model.PostalAddress;
import uk.gov.di.model.SocialSecurityRecordDetails;

import java.util.HashSet;
import java.util.Set;

@Data
@EqualsAndHashCode(callSuper = false)
@AllArgsConstructor
@NoArgsConstructor
@JsonInclude(JsonInclude.Include.NON_NULL)
public class SharedClaims extends BaseClaim {
    private Set<Name> name = new HashSet<>();
    private Set<BirthDate> birthDate = new HashSet<>();
    private Set<PostalAddress> address = new HashSet<>();
    private String emailAddress;
    private Set<SocialSecurityRecordDetails> socialSecurityRecord = new HashSet<>();
}
