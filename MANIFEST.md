# Test fixture for LLM Sanitizer

`sample-dirty.txt` is a deliberately contaminated text file. It has 58 lines,
2897 bytes and 2387 characters, so roughly 510 bytes are pure overhead from
things you cannot see. Line endings are CRLF on purpose, so the line ending rule
gets exercised too.

## What is in it

Section 1, invisible control characters
: U+200B ZWSP, U+200C ZWNJ, U+200D ZWJ, U+2060 word joiner, U+FEFF byte order
  mark in mid-line, U+00AD soft hyphen, U+202E bidi override closed by U+202C,
  U+2066 and U+2069 isolates, U+2062 invisible times, U+2800 braille blank,
  U+3164 Hangul filler.

Section 2, spaces
: U+00A0 NBSP, U+202F narrow NBSP, U+2000 en quad, U+2003 em space, U+2009 thin
  space, U+200A hair space, U+205F medium mathematical space, U+2028 line
  separator.

Section 3, typography
: em and en dash, U+2011 non-breaking hyphen, curly double and single quotes,
  low nine quotes, U+00B4 acute used as an apostrophe, U+2026 ellipsis, U+2025
  two dot leader, U+203C, U+2047, U+2048, U+2049, U+2022 bullets, U+2116 numero,
  U+00D7, U+2264, U+2192, U+2044 fraction slash, U+2105 care of, and the
  ligatures U+FB00 through U+FB06.

Section 4, lookalike characters
: Cyrillic o and A inside Latin words, plus a full Russian and a full Greek
  sentence that must come through untouched. Mathematical alphanumerics in five
  different styles, letterlike symbols including the Kelvin sign U+212A next to
  a plain K and the Angstrom sign U+212B, fullwidth U+FF21 to U+FF5A, and
  decomposed diacritics (e + U+0301, a + U+0303).

Section 5, steganographic payload
: three different carriers, each holding different content, so you can tell
  which decoder fired.

| Carrier | Encoding | Hidden content |
| --- | --- | --- |
| variation selectors | U+FE00-FE0F = byte 0-15, U+E0100-E01EF = byte 16-255 | `ROLID-TEST-2026` |
| tag characters | U+E0000 + ASCII codepoint | `user=martin;id=42` |
| zero width binary | U+200B = 0, U+200C = 1, eight bits per byte | `HI` |

Section 6, multilingual
: EN, DE, ES, CS and two Japanese lines. The Japanese part contains a kanji
  followed by IVS U+E0100, an ideographic space U+3000, fullwidth Test, a three
  dot leader U+2026, U+2015 and a wave dash U+301C. All of those are correct
  Japanese typography and the `ja` profile must leave them alone. There is also
  a family emoji joined by two ZWJ and a heart with VS16.

Section 7, whitespace
: double spaces, a space before a period, trailing spaces, three blank lines.

## Expected result

```
php llm-sanitizer.php --profile=en --lang=en < sample-dirty.txt > out.txt
```

The report should decode all three payloads and count around 220 changes. In the
output the following must hold:

- no codepoint in U+FE00-FE0F except the single VS16 after the heart emoji
- no codepoint in U+E0000-E01EF
- no ZWSP, ZWNJ, word joiner, BOM, soft hyphen or NBSP
- the family emoji stays one glyph, so the ZWJ between its parts survives
- the Russian and Greek sentences are byte identical to the input
- the kanji loses its IVS under the `en` profile, because that profile knows
  nothing about Japanese variant forms

```
php llm-sanitizer.php --profile=ja < sample-dirty.txt > out-ja.txt
```

Under the Japanese profile the kanji keeps its IVS, and U+3000, the fullwidth
letters, U+2026, U+2015 and U+301C all survive, while the hidden payloads and
the zero width characters are still removed.

## Shell checks

```
grep -P '[\x{FE00}-\x{FE0F}\x{E0000}-\x{E01EF}]' out.txt   # should print nothing
grep -P '[\x{200B}-\x{200F}\x{2060}\x{FEFF}\x{00AD}\x{00A0}]' out.txt
hexdump -C out.txt | grep -i 'f3 a0'                        # tag and VS byte prefix
```

The `f3 a0` prefix is worth remembering. Every codepoint in the U+E0000 plane
starts with those two bytes in UTF-8, so a single hexdump grep finds both tag
characters and supplementary variation selectors with no regex support at all.

## Files

- `sample-dirty.txt` input
- `sample-clean-en.txt` output of the English profile
- `sample-clean-ja.txt` output of the Japanese profile
- `report-en.txt`, `report-ja.txt` the corresponding stderr reports
