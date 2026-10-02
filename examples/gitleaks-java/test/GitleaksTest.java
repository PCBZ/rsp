import com.google.gson.JsonArray;
import com.google.gson.JsonElement;
import com.google.gson.JsonObject;
import com.google.gson.JsonParser;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;

/**
 * Line-and-column to byte offsets. No binary needed: a report is data.
 *
 * <p>The table is examples/gitleaks-offsets.json, shared with the other six
 * adapters, because the numbers in it are facts about gitleaks rather than
 * about any of them. What stays here is what this language makes possible.
 */
public final class GitleaksTest {
    private static int failures = 0;
    private static final String KEY = "AKIALALEMEL33243OLIB";

    private GitleaksTest() {}

    private static void check(boolean held, String what) {
        if (!held) {
            System.err.println("FAIL " + what);
            failures++;
        }
    }

    private static void theSharedTable() throws Exception {
        Path path = Path.of("..", "gitleaks-offsets.json");
        JsonObject table = JsonParser.parseString(Files.readString(path)).getAsJsonObject();
        JsonArray tests = table.getAsJsonArray("tests");
        // A path that resolved to nothing would leave this loop empty and green.
        check(tests.size() >= 13, "the table did not lose cases");

        for (JsonElement element : tests) {
            JsonObject test = element.getAsJsonObject();
            byte[] content = test.get("content").getAsString().getBytes(StandardCharsets.UTF_8);
            JsonArray want = test.getAsJsonArray("spans");
            JsonArray got = Spans.of(test.getAsJsonArray("findings"), content);
            String comment = test.get("comment").getAsString();

            if (want.isEmpty() && !test.getAsJsonArray("findings").isEmpty()) {
                check(got == null, comment);
            } else {
                check(got != null && got.equals(want), comment);
            }
        }
    }

    private static void offsetsAreBytesNotCodeUnits() {
        // An emoji is one character, two UTF-16 units and four bytes. Only the
        // last of those is what a span means, and String.length() is the
        // second — the same trap as TypeScript, in a language whose indices
        // look like character indices.
        String content = "😀 " + KEY;
        byte[] bytes = content.getBytes(StandardCharsets.UTF_8);

        check(content.length() == 2 + 1 + KEY.length(), "length() counts UTF-16 units");
        check(bytes.length == 4 + 1 + KEY.length(), "the span is measured in bytes");
        check(Spans.usable(5, 25, bytes), "the key starts at byte five");
        check(new String(bytes, 5, 20, StandardCharsets.UTF_8).equals(KEY), "and the bytes are it");
    }

    private static void spansTheHostWouldReject() {
        byte[] content = "密钥 AKIALALEMEL33243OLIB".getBytes(StandardCharsets.UTF_8);

        check(!Spans.usable(1, 3, content), "offsets inside a character are refused");
        check(!Spans.usable(0, 0, content), "an empty span is refused");
        check(!Spans.usable(-1, 5, content), "a negative start is refused");
        check(!Spans.usable(7, 400, content), "an end past the content is refused");
        check(Spans.usable(7, 27, content), "the key itself is usable");
    }

    public static void main(String[] args) throws Exception {
        theSharedTable();
        offsetsAreBytesNotCodeUnits();
        spansTheHostWouldReject();
        if (failures > 0) {
            System.err.println(failures + " failed");
            System.exit(1);
        }
        System.out.println("ok");
    }
}
