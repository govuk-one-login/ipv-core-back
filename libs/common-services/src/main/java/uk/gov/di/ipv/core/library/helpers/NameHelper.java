package uk.gov.di.ipv.core.library.helpers;

import uk.gov.di.model.Name;
import uk.gov.di.model.NamePart;

import java.util.List;

public class NameHelper {
    private NameHelper() {}

    public static Name createName(List<NamePart> nameParts) {
        var name = new Name();
        name.setNameParts(nameParts);
        return name;
    }

    public static class NamePartHelper {
        private NamePartHelper() {}

        public static NamePart createNamePart(String value, NamePart.NamePartType type) {
            var namePart = new NamePart();
            namePart.setValue(value);
            namePart.setType(type);
            return namePart;
        }
    }
}
