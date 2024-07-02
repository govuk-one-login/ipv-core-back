package uk.gov.di.ipv.core.library.domain;

import com.fasterxml.jackson.core.JacksonException;
import com.fasterxml.jackson.core.JsonParser;
import com.fasterxml.jackson.databind.DeserializationContext;
import com.fasterxml.jackson.databind.deser.std.StdDeserializer;

import java.io.IOException;

public class CriDeserializer extends StdDeserializer<Cri> {

    public CriDeserializer() {
        this(null);
    }

    public CriDeserializer(Class<Cri> c) {
        super(c);
    }

    @Override
    public Cri deserialize(JsonParser p, DeserializationContext ctxt)
            throws IOException, JacksonException {
        return Cri.fromId(p.getText());
    }
}
