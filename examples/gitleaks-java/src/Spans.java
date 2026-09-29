import com.google.gson.JsonArray;
import com.google.gson.JsonElement;
import com.google.gson.JsonObject;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

/** Line-and-column positions from a gitleaks report, as byte offsets (S1). */
final class Spans {
    private Spans() {}

    /**
     * Converts a report into spans, or null if any finding could not be placed.
     *
     * <p>gitleaks counts a line's columns from the newline byte that ended the
     * previous line, so only line one matches the 1-based column anyone
     * assumes. EndColumn belongs to EndLine, which differs whenever a finding
     * spans lines. Anything that does not slice Match back out is refused, and
     * the caller turns that into a BLOCK.
     */
    static JsonArray of(JsonArray findings, byte[] content) {
        List<Integer> origins = lineStarts(content);
        JsonArray spans = new JsonArray();

        for (JsonElement element : findings) {
            JsonObject finding = element.getAsJsonObject();
            long from = origin(origins, number(finding, "StartLine"));
            long to = origin(origins, number(finding, "EndLine"));
            if (from < 0 || to < 0) {
                return null;
            }
            long start = from + number(finding, "StartColumn") - 1;
            long end = to + number(finding, "EndColumn");
            byte[] match = text(finding, "Match").getBytes(java.nio.charset.StandardCharsets.UTF_8);

            if (!usable(start, end, content) || end - start != match.length
                    || !Arrays.equals(content, (int) start, (int) end, match, 0, match.length)) {
                return null;
            }
            JsonObject span = new JsonObject();
            span.addProperty("start", start);
            span.addProperty("end", end);
            span.addProperty("type", text(finding, "RuleID"));
            spans.add(span);
        }
        return spans;
    }

    /** In range, non-empty, and on a character boundary at both ends (S3). */
    static boolean usable(long start, long end, byte[] content) {
        if (start < 0 || end <= start || end > content.length) {
            return false;
        }
        for (long at : new long[] {start, end}) {
            // A continuation byte is 0b10xxxxxx; a boundary is anything else.
            if (at != 0 && at != content.length && (content[(int) at] & 0xC0) == 0x80) {
                return false;
            }
        }
        return true;
    }

    /** The byte gitleaks counts this line's columns from, or -1. */
    private static long origin(List<Integer> starts, long line) {
        if (line == 1) {
            return 0;
        }
        if (line < 1 || line > starts.size()) {
            return -1;
        }
        return starts.get((int) line - 1) - 1L;
    }

    private static List<Integer> lineStarts(byte[] content) {
        List<Integer> starts = new ArrayList<>(List.of(0));
        for (int at = 0; at < content.length; at++) {
            if (content[at] == '\n') {
                starts.add(at + 1);
            }
        }
        return starts;
    }

    private static long number(JsonObject finding, String name) {
        JsonElement value = finding.get(name);
        return value != null && value.isJsonPrimitive() ? value.getAsLong() : 0;
    }

    private static String text(JsonObject finding, String name) {
        JsonElement value = finding.get(name);
        return value != null && value.isJsonPrimitive() ? value.getAsString() : "";
    }
}
