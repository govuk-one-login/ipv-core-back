package uk.gov.di.ipv.core.callticfcri.helpers;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.nimbusds.jose.util.Base64URL;
import org.apache.commons.io.FileUtils;

import java.io.File;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Paths;

public class JwtTestHelper {
    private static final ObjectMapper objectMapper = new ObjectMapper();
    private final String minifiedHeaderJson;
    private final String minifiedBodyJson;
    private final String signature;
    private static final String PREFIX = "src/test/resources";

    public JwtTestHelper(String pathname) throws IOException {
        this.minifiedHeaderJson = minifyJson(readFile("validHeader.json", ""));
        this.minifiedBodyJson = minifyJson(readFile(pathname, "body.json"));
        this.signature = readFile(pathname, "signature").trim();
    }

    public String buildJwt() {
        return Base64URL.encode(minifiedHeaderJson)
                + "."
                + Base64URL.encode(minifiedBodyJson)
                + "."
                + signature;
    }

    public String buildRegexMatcherIgnoringSignature() {
        return "^"
                + Base64URL.encode(minifiedHeaderJson)
                + "\\."
                + Base64URL.encode(minifiedBodyJson)
                + "\\..*";
    }

    private String minifyJson(String prettyJson) {
        JsonNode jsonNode;
        try {
            jsonNode = objectMapper.readValue(prettyJson, JsonNode.class);
        } catch (JsonProcessingException e) {
            throw new RuntimeException(e);
        }
        return jsonNode.toString();
    }

    private String readFile(String path, String suffix) throws IOException {
        var pathname = Paths.get(JwtTestHelper.PREFIX, path, suffix);

        return FileUtils.readFileToString(new File(pathname.toUri()), StandardCharsets.UTF_8);
    }
}
