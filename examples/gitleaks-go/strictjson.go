package main

// One message, refusing what a lenient parser would take (T4).
//
// encoding/json already refuses NaN, a leading zero and a byte order mark.
// What it takes and T4 does not: a repeated key, an integer JavaScript would
// round, and a lone surrogate, which it replaces with U+FFFD rather than
// refusing.

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"unicode/utf16"
)

// safeInteger is the largest a JavaScript number carries exactly.
const safeInteger = 1<<53 - 1

// strictUnmarshal parses one message, or says which leniency it relied on.
func strictUnmarshal(raw []byte, into any) error {
	if err := refuseLeniency(raw); err != nil {
		return err
	}
	return json.Unmarshal(raw, into)
}

// refuseLeniency walks the tokens for what the grammar does not allow.
func refuseLeniency(raw []byte) error {
	if err := refuseLoneSurrogate(raw); err != nil {
		return err
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.UseNumber()
	return walk(decoder)
}

// walk reads one value, refusing a repeated key or an unsafe integer.
func walk(decoder *json.Decoder) error {
	for {
		token, err := decoder.Token()
		if err != nil {
			return nil // end of the message, or a parse error Unmarshal will name
		}
		switch value := token.(type) {
		case json.Delim:
			if value == '{' {
				if err := object(decoder); err != nil {
					return err
				}
			}
		case json.Number:
			if err := checkNumber(value); err != nil {
				return err
			}
		}
	}
}

// object reads one object's members, refusing a key it has already seen.
func object(decoder *json.Decoder) error {
	seen := map[string]bool{}
	for decoder.More() {
		key, err := decoder.Token()
		if err != nil {
			return err
		}
		name, _ := key.(string)
		if seen[name] {
			return fmt.Errorf("repeated key %q", name)
		}
		seen[name] = true

		value, err := decoder.Token()
		if err != nil {
			return err
		}
		switch inner := value.(type) {
		case json.Delim:
			if inner == '{' {
				if err := object(decoder); err != nil {
					return err
				}
			} else if inner == '[' {
				if err := array(decoder); err != nil {
					return err
				}
			}
		case json.Number:
			if err := checkNumber(inner); err != nil {
				return err
			}
		}
	}
	_, err := decoder.Token() // the closing brace
	return err
}

func array(decoder *json.Decoder) error {
	for decoder.More() {
		token, err := decoder.Token()
		if err != nil {
			return err
		}
		switch inner := token.(type) {
		case json.Delim:
			if inner == '{' {
				if err := object(decoder); err != nil {
					return err
				}
			} else if inner == '[' {
				if err := array(decoder); err != nil {
					return err
				}
			}
		case json.Number:
			if err := checkNumber(inner); err != nil {
				return err
			}
		}
	}
	_, err := decoder.Token()
	return err
}

func checkNumber(number json.Number) error {
	if strings.ContainsAny(number.String(), ".eE") {
		return nil // a float is not the integer T4 bounds
	}
	whole, err := number.Int64()
	if err != nil || whole > safeInteger || whole < -safeInteger {
		return fmt.Errorf("%s is outside ±(2^53 - 1)", number)
	}
	return nil
}

// refuseLoneSurrogate reads the \uXXXX escapes, which encoding/json turns into
// U+FFFD rather than refusing.
func refuseLoneSurrogate(raw []byte) error {
	text := string(raw)
	for at := 0; at+6 <= len(text); at++ {
		if text[at] != '\\' || text[at+1] != 'u' {
			continue
		}
		var first uint16
		if _, err := fmt.Sscanf(text[at+2:at+6], "%04x", &first); err != nil {
			continue
		}
		if !utf16.IsSurrogate(rune(first)) {
			continue
		}
		if at+12 > len(text) || text[at+6] != '\\' || text[at+7] != 'u' {
			return errors.New("unpaired surrogate")
		}
		var second uint16
		if _, err := fmt.Sscanf(text[at+8:at+12], "%04x", &second); err != nil {
			return errors.New("unpaired surrogate")
		}
		if utf16.DecodeRune(rune(first), rune(second)) == 0xFFFD {
			return errors.New("unpaired surrogate")
		}
		at += 11
	}
	return nil
}
