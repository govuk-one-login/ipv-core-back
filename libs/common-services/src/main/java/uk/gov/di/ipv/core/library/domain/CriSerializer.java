package uk.gov.di.ipv.core.library.domain;

import com.fasterxml.jackson.core.JsonGenerator;
import com.fasterxml.jackson.databind.SerializerProvider;
import com.fasterxml.jackson.databind.ser.std.StdSerializer;

import java.io.IOException;

public class CriSerializer extends StdSerializer<Cri> {

    public CriSerializer() {
        this(null);
    }

    public CriSerializer(Class<Cri> c) {
        super(c);
    }

    @Override
    public void serialize(Cri value, JsonGenerator gen, SerializerProvider provider)
            throws IOException {
        gen.writeString(value.getId());
    }
}
