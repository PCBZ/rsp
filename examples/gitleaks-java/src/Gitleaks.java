import com.google.gson.JsonArray;
import com.google.gson.JsonElement;
import com.google.gson.JsonParser;
import java.io.IOException;
import java.io.OutputStream;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;

/**
 * Wraps the gitleaks binary, through its {@code stdin} command and its report.
 *
 * <p>Everything here is bytes. A Java {@code String} is a sequence of UTF-16
 * code units, so its indices are not the byte offsets S1 requires and
 * {@code length()} is not a byte count: an emoji is one character, two units
 * and four bytes. The content is encoded once and never indexed as text.
 */
final class Gitleaks {
    /** Separates "found something" from gitleaks failing, which shares 1. */
    static final int FOUND = 2;

    private Gitleaks() {}

    static String binary() {
        String override = System.getenv("RSP_GITLEAKS");
        return (override == null || override.isEmpty()) ? "gitleaks" : override;
    }

    /**
     * Runs the binary once, returning what it wrote and how it exited.
     *
     * <p>stdin is fed from another thread. ProcessBuilder pumps nothing, so
     * writing the chunk and then reading the report would deadlock against a
     * tool that fills its stdout pipe before draining stdin.
     */
    static Run run(List<String> args, byte[] input) throws IOException, InterruptedException {
        List<String> command = new ArrayList<>();
        command.add(binary());
        command.addAll(args);
        // Inherited, not piped: a pipe nobody reads stops the tool once it
        // fills, and gitleaks writes what it scanned to stderr. Diagnostics
        // belong on ours anyway, where they are not the protocol's (T2, E3).
        Process child = new ProcessBuilder(command)
                .redirectError(ProcessBuilder.Redirect.INHERIT)
                .start();

        Thread writer = new Thread(() -> {
            try (OutputStream stdin = child.getOutputStream()) {
                stdin.write(input);
            } catch (IOException closedEarly) {
                // The tool stopped reading; its exit status is what says why.
            }
        });
        writer.start();

        byte[] out = child.getInputStream().readAllBytes();
        int status = child.waitFor();
        writer.join();
        return new Run(new String(out, StandardCharsets.UTF_8).trim(), status);
    }

    record Run(String report, int status) {}

    /** Carried in the declaration so a cache key includes it (D4). */
    static String version() throws IOException, InterruptedException {
        return accepted(run(List.of("version"), new byte[0])).report();
    }

    /** 0 or FOUND and nothing else: an unknown status is a run we cannot read. */
    private static Run accepted(Run run) throws IOException {
        if (run.status() != 0 && run.status() != FOUND) {
            throw new IOException("gitleaks exited with " + run.status());
        }
        return run;
    }

    /** The findings for one chunk. */
    static JsonArray scan(byte[] content) throws IOException, InterruptedException {
        // "-" is gitleaks' own spelling of stdout; /dev/stdout fails its
        // writability pre-check. --no-banner keeps stdout to the report alone.
        Run run = accepted(run(List.of("stdin", "--no-banner", "--report-format", "json",
                "--report-path", "-", "--exit-code", "2"), content));
        // Exit 0 with nothing written is a clean chunk. Exit 2 is gitleaks
        // saying it found something, so nothing written is a report that went
        // missing, and no findings is the ALLOW E1 refuses.
        if (run.report().isEmpty()) {
            if (run.status() == FOUND) {
                throw new IOException("gitleaks reported findings and wrote no report");
            }
            return new JsonArray();
        }
        JsonElement parsed = JsonParser.parseString(run.report());
        if (!parsed.isJsonArray()) {
            throw new IOException("gitleaks wrote a report that is not a list of findings");
        }
        return parsed.getAsJsonArray();
    }
}
