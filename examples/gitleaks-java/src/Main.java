import com.google.gson.JsonElement;
import com.google.gson.JsonParser;
import java.io.PrintStream;
import java.nio.charset.StandardCharsets;

/**
 * One JSON object in, one out, then exit (T1).
 *
 * <p>Diagnostics go to stderr: a stray line on stdout is indistinguishable
 * from a response (T2). Any failure exits non-zero having written nothing to
 * stdout, which is how a plugin says it could not judge the chunk (E1, D3).
 */
public final class Main {
    private Main() {}

    public static void main(String[] args) {
        PrintStream out = new PrintStream(System.out, true, StandardCharsets.UTF_8);
        try {
            String raw = new String(System.in.readAllBytes(), StandardCharsets.UTF_8);
            JsonElement request = JsonParser.parseString(raw);
            if (!request.isJsonObject()) {
                throw new IllegalArgumentException("the request is not a JSON object");
            }
            out.println(Protocol.respond(request.getAsJsonObject()));
        } catch (Exception failed) {
            System.err.println("rsp-gitleaks-java: " + failed.getMessage());
            System.exit(1);
        }
    }
}
