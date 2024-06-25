package uk.gov.di.ipv.core.library.helpers;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;
import org.mockito.junit.jupiter.MockitoExtension;

import java.util.stream.Stream;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

@ExtendWith(MockitoExtension.class)
class CollectionHelperTest {
    @Test
    void shouldReturnSingletonForStreamOfOne() {
        // Act
        var result = Stream.of("a").collect(CollectionHelper.toSingleton());

        // Assert
        assertEquals("a", result);
    }

    @ParameterizedTest
    @MethodSource("nonSingletonStreams")
    void shouldThrowForStreamOfMultiple(Stream<String> nonSingletonStream) {
        // Act
        var exception =
                assertThrows(
                        IllegalStateException.class,
                        () -> nonSingletonStream.collect(CollectionHelper.toSingleton()));

        // Assert
        assertEquals("List size is not 1", exception.getMessage());
    }

    private static Stream<Arguments> nonSingletonStreams() {
        return Stream.of(Arguments.of(Stream.of()), Arguments.of(Stream.of("a", "b")));
    }
}
