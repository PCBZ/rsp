import com.google.gson.JsonElement;
import com.google.gson.JsonObject;
import com.google.gson.stream.JsonReader;
import com.google.gson.stream.JsonToken;
import com.google.gson.stream.MalformedJsonException;
import java.io.IOException;
import java.io.StringReader;
import java.math.BigInteger;
import java.nio.ByteBuffer;
import java.nio.charset.CharacterCodingException;
import java.nio.charset.CharsetDecoder;
import java.nio.charset.CodingErrorAction;
import java.nio.charset.StandardCharsets;
import java.util.HashSet;
import java.util.Set;

/**
 * One message, refusing what a lenient parser would take (T4).
 *
 * <p>gson in strict mode refuses NaN and a leading zero. What it takes and T4
 * does not: a repeated key, an integer JavaScript would round, a byte order
 * mark, and a lone surrogate. Decoding is separate again: {@code new
 * String(bytes, UTF_8)} substitutes U+FFFD rather than failing, so malformed
 * bytes would become a chunk the host never sent.
 */
final class StrictJson {
    /** The largest a JavaScript number carries exactly. */
    private static final BigInteger SAFE_INTEGER = BigInteger.valueOf((1L << 53) - 1);

    private StrictJson() {}

    /** The request's text, or an exception naming why these bytes are not one. */
    static String decode(byte[] raw) throws IOException {
        CharsetDecoder decoder = StandardCharsets.UTF_8.newDecoder()
                .onMalformedInput(CodingErrorAction.REPORT)
                .onUnmappableCharacter(CodingErrorAction.REPORT);
        try {
            return decoder.decode(ByteBuffer.wrap(raw)).toString();
        } catch (CharacterCodingException notUtf8) {
            throw new IOException("the request is not UTF-8", notUtf8);
        }
    }

    /** Parses one message, or throws naming the leniency it relied on. */
    static JsonObject parse(String raw) throws IOException {
        if (!raw.isEmpty() && raw.charAt(0) == '﻿') {
            throw new MalformedJsonException("a byte order mark is not whitespace");
        }

        JsonReader reader = new JsonReader(new StringReader(raw));
        reader.setStrictness(com.google.gson.Strictness.STRICT);
        JsonElement value = walk(reader);
        if (reader.peek() != JsonToken.END_DOCUMENT) {
            throw new MalformedJsonException("more than one value");
        }
        if (!value.isJsonObject()) {
            throw new MalformedJsonException("the request is not a JSON object");
        }
        return value.getAsJsonObject();
    }

    /** One value, refusing a repeated key or an integer out of range. */
    private static JsonElement walk(JsonReader reader) throws IOException {
        switch (reader.peek()) {
            case BEGIN_OBJECT -> {
                JsonObject object = new JsonObject();
                Set<String> seen = new HashSet<>();
                reader.beginObject();
                while (reader.hasNext()) {
                    String name = reader.nextName();
                    refuseLoneSurrogate(name);
                    if (!seen.add(name)) {
                        throw new MalformedJsonException("repeated key \"" + name + "\"");
                    }
                    object.add(name, walk(reader));
                }
                reader.endObject();
                return object;
            }
            case BEGIN_ARRAY -> {
                com.google.gson.JsonArray array = new com.google.gson.JsonArray();
                reader.beginArray();
                while (reader.hasNext()) {
                    array.add(walk(reader));
                }
                reader.endArray();
                return array;
            }
            case NUMBER -> {
                String literal = reader.nextString();
                return new com.google.gson.JsonPrimitive(checkedNumber(literal));
            }
            case STRING -> {
                String text = reader.nextString();
                refuseLoneSurrogate(text);
                return new com.google.gson.JsonPrimitive(text);
            }
            case BOOLEAN -> {
                return new com.google.gson.JsonPrimitive(reader.nextBoolean());
            }
            case NULL -> {
                reader.nextNull();
                return com.google.gson.JsonNull.INSTANCE;
            }
            default -> throw new MalformedJsonException("unexpected " + reader.peek());
        }
    }

    private static Number checkedNumber(String literal) throws IOException {
        if (literal.contains(".") || literal.contains("e") || literal.contains("E")) {
            return Double.valueOf(literal); // a float is not the integer T4 bounds
        }
        BigInteger whole = new BigInteger(literal);
        if (whole.abs().compareTo(SAFE_INTEGER) > 0) {
            throw new MalformedJsonException(literal + " is outside the safe integer range");
        }
        return whole.longValueExact();
    }

    /** A lone surrogate parses and cannot be written back as UTF-8 (M1). */
    private static void refuseLoneSurrogate(String raw) throws IOException {
        for (int at = 0; at < raw.length(); at++) {
            char unit = raw.charAt(at);
            if (Character.isHighSurrogate(unit)) {
                if (at + 1 >= raw.length() || !Character.isLowSurrogate(raw.charAt(at + 1))) {
                    throw new MalformedJsonException("unpaired surrogate");
                }
                at++;
            } else if (Character.isLowSurrogate(unit)) {
                throw new MalformedJsonException("unpaired surrogate");
            }
        }
    }
}
