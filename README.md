# LLM Sanitizer

Single file PHP tool that strips invisible characters, steganographic carriers
and typographic artifacts from LLM output. The wording of the text is never
touched, only characters that carry no meaning of their own.

No Composer, no ext-mbstring, no database, nothing stored. Drop the file on any
PHP 7.4+ host and open it, or pipe text through it on the command line.
ext-intl is optional and only improves NFC handling and Unicode character names.

UI in English, German, Spanish, Czech and Japanese.

## Why

Text produced by a language model carries a fingerprint even after you edit the
wording. Some of it is harmless typography, some of it is a deliberate carrier.
Two categories can hold an arbitrary payload that is completely invisible in
every editor:

* Variation selectors, U+FE00-FE0F and U+E0100-E01EF. Sixteen plus 240 values
  map cleanly onto a byte, so any string can be appended to a single character.
* Unicode tag characters, U+E0020-E007E, which are a direct copy of printable
  ASCII with zero rendering.

LLM Sanitizer decodes both before removing them, so you see what was hidden.
Zero width runs are additionally decoded best effort as binary.

## What it removes

Invisible carriers
: zero width space, ZWNJ, ZWJ, word joiner, BOM, soft hyphen, combining
  grapheme joiner, bidi embeddings, overrides and isolates, invisible math
  operators, deprecated format characters, interlinear annotation, musical
  format controls, Mongolian variation selectors, Hangul fillers, braille
  blank, the whole Unicode tag block, variation selectors.

Typography
: em, en and figure dashes, non-breaking hyphen, minus sign, curly quotes and
  apostrophes, modifier letter apostrophes, ellipsis, two dot leader, bullets,
  fraction slash, numero, care of, arrows, multiplication and division signs,
  comparison operators.

Spaces
: NBSP, narrow NBSP, the U+2000-200A family, medium mathematical space,
  ogham space, ideographic space, line and paragraph separators.

Lookalikes
: Cyrillic and Greek homoglyphs inside Latin words, mathematical alphanumeric
  symbols and the letterlike symbols that fill the holes in that block,
  fullwidth forms, typographic ligatures, Kelvin and Angstrom signs.

Encoding level
: malformed UTF-8, decomposed diacritics recomposed to NFC, CRLF line endings,
  trailing whitespace, repeated spaces, space before punctuation, runs of
  blank lines.

After cleaning, an audit table lists every character still outside the keyboard
range for the selected profile, with codepoint and Unicode name. That is the
safety net for carriers the rule set does not know about.

## Language profiles

The profile decides both the default rule set and what counts as a keyboard
character in the audit.

| Profile | Behaviour |
| --- | --- |
| en | ASCII only, all rules on |
| de | umlauts and eszett kept |
| es | accents, enye, inverted marks kept |
| cs | Latin-1 and Latin Extended-A kept |
| ja | fullwidth forms, ideographic space, three dot leader, wave dash and U+2015 kept; IVS after a kanji kept; invisible carriers still removed |
| universal | major scripts kept, homoglyph rule off |

The Japanese profile matters. U+E0100-E01EF after a CJK ideograph is a
legitimate Ideographic Variation Sequence, not a watermark, and stripping it
changes which glyph is displayed. Fullwidth punctuation and U+3000 are correct
Japanese typography. The profile keeps all of those while still removing zero
width characters, tag characters and variation selector payloads attached to
non-CJK characters.

## Command line

```
php llm-sanitizer.php < in.txt > out.txt
php llm-sanitizer.php --report --profile=ja --lang=ja < in.txt
php llm-sanitizer.php --no-tidy --no-spaces --guillemets < in.txt
php llm-sanitizer.php --help
```

The cleaned text goes to stdout, the report and the audit go to stderr, so
piping stays clean. Every rule can be forced on with `--rule` or off with
`--no-rule`.

## What it cannot do

Character cleaning does not remove a statistical watermark such as SynthID or a
green list scheme. Those are encoded in the choice of tokens, not in the
characters, and survive any amount of character normalisation. The only thing
that removes them is rewriting the text.

## License

MIT. See LICENSE.
