package io.github.probityai.keycloak.evidence;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

import java.util.Arrays;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

import org.junit.jupiter.api.Test;

class CanonicalJsonTest {

    @Test
    void sortsKeysAndWritesNoWhitespace() {
        Map<String, Object> value = new LinkedHashMap<>();
        value.put("b", List.of(1L, true, "x"));
        value.put("a", Arrays.asList((Object) null));
        assertEquals("{\"a\":[null],\"b\":[1,true,\"x\"]}", CanonicalJson.write(value));
    }

    @Test
    void escapesControlAndNonAsciiCharacters() {
        assertEquals("\"q\\\"\\\\\\n\\u0001\\u00e9\"", CanonicalJson.write("q\"\\\n\u0001é"));
    }

    @Test
    void refusesUnsupportedValues() {
        assertThrows(IllegalArgumentException.class, () -> CanonicalJson.write(1.5d));
    }
}
