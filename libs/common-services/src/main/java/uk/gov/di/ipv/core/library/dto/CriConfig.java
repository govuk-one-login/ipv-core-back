package uk.gov.di.ipv.core.library.dto;

import com.nimbusds.jose.jwk.ECKey;
import lombok.AllArgsConstructor;
import lombok.EqualsAndHashCode;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.experimental.SuperBuilder;

import java.text.ParseException;

@AllArgsConstructor
@NoArgsConstructor
@SuperBuilder
@EqualsAndHashCode
@Getter
public class CriConfig {
    private String componentId;
    private String signingKey;

    public ECKey getParsedSigningKey() throws ParseException {
        return ECKey.parse(signingKey);
    }
}
