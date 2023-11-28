package uk.gov.di.ipv.core.library.dto;

import com.nimbusds.jose.jwk.ECKey;

import java.net.URI;
import java.text.ParseException;

public interface CriConfig {
    URI getCredentialUrl();

    ECKey getSigningKey() throws ParseException;

    String getComponentId();
}
