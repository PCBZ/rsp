import com.google.gson.JsonArray;
import com.google.gson.JsonElement;
import com.google.gson.JsonObject;
import java.io.IOException;
import java.nio.charset.StandardCharsets;

/** The shape SPEC.md requires, in one file, for whoever ports this again. */
final class Protocol {
    static final String REPLACEMENT = "[REDACTED:secret]";

    private Protocol() {}

    /** What this plugin says it is (H2). */
    private static JsonObject declare() throws IOException, InterruptedException {
        JsonArray hooks = new JsonArray();
        hooks.add("on_chunk");
        hooks.add("on_retrieve");
        JsonObject declaration = new JsonObject();
        declaration.addProperty("rsp_version", "0.1");
        declaration.addProperty("name", "rsp-gitleaks-java");
        // The version carries the binary's: for a wrapper it is the tool that
        // decides verdicts, and the cache is keyed on this string (D4).
        declaration.addProperty("version", "0.1.0+" + Gitleaks.version());
        declaration.add("hooks", hooks);
        declaration.addProperty("deterministic", true);
        return declaration;
    }

    /** Unrecognized request fields are ignored, never an error (D8). */
    static JsonObject respond(JsonObject request) throws IOException, InterruptedException {
        if ("handshake".equals(string(request, "hook"))) {
            return declare();
        }
        // Encoded once: every offset below indexes these bytes, and a String
        // is indexed by UTF-16 code unit.
        byte[] content = string(request, "content").getBytes(StandardCharsets.UTF_8);

        JsonArray findings = Gitleaks.scan(content);
        // ALLOW carries nothing else: the common case is the cheap one (V2).
        if (findings.isEmpty()) {
            return verdict("ALLOW");
        }
        JsonArray spans = Spans.of(findings, content);
        // A finding with no span is a secret we cannot point at; redacting the
        // rest would leave it in the chunk (V4).
        if (spans == null) {
            JsonObject blocked = verdict("BLOCK");
            blocked.addProperty("reason",
                    "gitleaks reported a finding whose position could not be confirmed");
            blocked.addProperty("severity", "critical");
            return blocked;
        }
        JsonObject redact = verdict("REDACT");
        redact.add("spans", spans);
        redact.addProperty("replacement", REPLACEMENT);
        redact.addProperty("severity", "critical");
        return redact;
    }

    private static JsonObject verdict(String name) {
        JsonObject response = new JsonObject();
        response.addProperty("verdict", name);
        return response;
    }

    private static String string(JsonObject object, String name) {
        JsonElement value = object.get(name);
        return value != null && value.isJsonPrimitive() ? value.getAsString() : "";
    }
}
