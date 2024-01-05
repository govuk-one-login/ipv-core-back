package uk.gov.di.ipv.core.library.dto;

import com.nimbusds.jose.jwk.ECKey;
import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.experimental.SuperBuilder;

import java.text.ParseException;

@AllArgsConstructor
@NoArgsConstructor
@SuperBuilder
public class CriConfig {
    @Getter private String componentId;
    private String signingKey;

    public ECKey getSigningKey() throws ParseException {
        return ECKey.parse(signingKey);
    }
}
