<?php
declare(strict_types=1);

/**
 * LLM Sanitizer - single file text cleaner.
 *
 * Removes invisible characters, steganographic carriers and typographic
 * artifacts that LLM output typically carries, while keeping the text itself
 * unchanged (same words, same meaning).
 *
 * Web UI in EN / DE / ES / CS / JA. Language profiles adapt the rule set:
 * Japanese keeps fullwidth forms, ideographic space and IVS sequences,
 * Spanish keeps the inverted marks, German and Czech keep their diacritics.
 *
 * Usage:
 *   web : drop the file on any PHP 7.4+ host and open it in a browser
 *   cli : php llm-sanitizer.php < in.txt > out.txt
 *         php llm-sanitizer.php --report --profile=ja < in.txt
 *         php llm-sanitizer.php --no-tidy --no-spaces < in.txt
 *
 * No Composer, no ext-mbstring. ext-intl optional (better NFC + char names).
 *
 * SPDX-License-Identifier: MIT
 * Copyright (c) 2026 Rolid spol. s r.o.
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 */

final class LlmSanitizer
{
    public const VERSION = '1.0.0';

    /** Rule switches, all boolean, all exposed in the UI and on the CLI. */
    public const DEFAULTS = [
        'hidden'     => true,  // decode steganographic payloads before stripping
        'invisible'  => true,  // zero width, joiners, bidi, BOM, tags, fillers
        'varsel'     => true,  // variation selectors FE00-FE0F, E0100-E01EF
        'keep_emoji' => true,  // keep VS16 when it really follows an emoji
        'keep_ivs'   => false, // keep E0100-E01EF after a CJK ideograph
        'spaces'     => true,  // NBSP, NNBSP, en/em/thin/hair space, U+2028/9
        'dashes'     => true,  // em/en/figure/minus/non-breaking hyphen
        'quotes'     => true,  // curly quotes, primes, modifier apostrophes
        'guillemets' => false, // << >> - off by default, often real content
        'punct'      => true,  // ellipsis, bullets, numero, care of
        'symbols'    => true,  // arrows, x, <=, >=, !=
        'fullwidth'  => true,  // FF01-FF5E, ideographic space
        'mathalnum'  => true,  // mathematical alphanumerics + letterlike
        'ligatures'  => true,  // fi fl ff ffi ffl st
        'homoglyph'  => true,  // Cyrillic/Greek lookalikes inside Latin words
        'nfc'        => true,  // recompose decomposed diacritics
        'tidy'       => true,  // CRLF, trailing spaces, multi spaces, blank lines
    ];

    /**
     * Per language deviations from DEFAULTS.
     * Japanese is the big one: fullwidth forms, the ideographic space, the
     * three dot leader and the wave dash are correct typography there, and
     * E0100-E01EF after a kanji is a legitimate Ideographic Variation Sequence,
     * not a watermark.
     */
    public const PROFILE_OVERRIDES = [
        'en' => [],
        'de' => [],
        'es' => [],
        'cs' => [],
        'ja' => [
            'fullwidth' => false, 'dashes' => false, 'punct' => false,
            'quotes' => false, 'symbols' => false, 'keep_ivs' => true,
        ],
        'universal' => ['homoglyph' => false, 'fullwidth' => false],
    ];

    /** Extra codepoints considered "reachable on the keyboard" per profile. */
    private const ALLOW = [
        'en' => '',
        'de' => '\x{00C4}\x{00D6}\x{00DC}\x{00E4}\x{00F6}\x{00FC}\x{00DF}\x{20AC}',
        'es' => '\x{00C1}\x{00C9}\x{00CD}\x{00D1}\x{00D3}\x{00DA}\x{00DC}\x{00E1}\x{00E9}'
              . '\x{00ED}\x{00F1}\x{00F3}\x{00FA}\x{00FC}\x{00A1}\x{00BF}\x{20AC}',
        'cs' => '\x{00C0}-\x{017F}\x{20AC}',
        'ja' => '\x{00A5}\x{20AC}\x{3000}-\x{303F}\x{3040}-\x{309F}\x{30A0}-\x{30FF}'
              . '\x{31F0}-\x{31FF}\x{3400}-\x{4DBF}\x{4E00}-\x{9FFF}\x{F900}-\x{FAFF}'
              . '\x{FF00}-\x{FFEF}',
        'universal' => '\x{00A1}-\x{024F}\x{0370}-\x{03FF}\x{0400}-\x{04FF}\x{0590}-\x{05FF}'
              . '\x{0600}-\x{06FF}\x{0E00}-\x{0E7F}\x{3000}-\x{30FF}\x{3400}-\x{4DBF}'
              . '\x{4E00}-\x{9FFF}\x{AC00}-\x{D7AF}\x{FF00}-\x{FFEF}\x{20AC}',
    ];

    /** @var array<string,int> */
    private array $report = [];
    /** @var array<int,array{type:string,payload:string}> */
    private array $hidden = [];
    private array $opt;
    private string $profile;

    public function __construct(array $opt = [], string $profile = 'en')
    {
        $this->profile = isset(self::ALLOW[$profile]) ? $profile : 'en';
        $this->opt = $opt + self::profileDefaults($this->profile);
    }

    public static function profileDefaults(string $profile): array
    {
        return (self::PROFILE_OVERRIDES[$profile] ?? []) + self::DEFAULTS;
    }

    // ---------------------------------------------------------------- public

    public function run(string $s): string
    {
        $this->report = [];
        $this->hidden = [];
        if ($s === '') { return ''; }

        // Drop malformed UTF-8 first, otherwise every /u regex silently bails out.
        $clean = @iconv('UTF-8', 'UTF-8//IGNORE', $s);
        if ($clean !== false && $clean !== $s) {
            $this->log('broken_utf8', 1);
            $s = $clean;
        }

        if ($this->opt['hidden'])     { $this->decodeHidden($s); }
        if ($this->opt['nfc'])        { $s = $this->nfc($s); }
        if ($this->opt['invisible'])  { $s = $this->invisible($s); }
        if ($this->opt['varsel'])     { $s = $this->varsel($s); }
        if ($this->opt['spaces'])     { $s = $this->spaces($s); }
        if ($this->opt['fullwidth'])  { $s = $this->fullwidth($s); }
        if ($this->opt['mathalnum'])  { $s = $this->mathAlnum($s); }
        if ($this->opt['ligatures'])  { $s = $this->ligatures($s); }
        if ($this->opt['quotes'])     { $s = $this->quotes($s); }
        if ($this->opt['guillemets']) { $s = $this->guillemets($s); }
        if ($this->opt['dashes'])     { $s = $this->dashes($s); }
        if ($this->opt['punct'])      { $s = $this->punct($s); }
        if ($this->opt['symbols'])    { $s = $this->symbols($s); }
        if ($this->opt['homoglyph'])  { $s = $this->homoglyphs($s); }
        if ($this->opt['tidy'])       { $s = $this->tidy($s); }

        return $s;
    }

    public function report(): array { return $this->report; }
    public function hidden(): array { return $this->hidden; }
    public function profile(): string { return $this->profile; }
    public function options(): array { return $this->opt; }

    /**
     * Everything left that is not reachable on a keyboard for this profile.
     * @return array<int,array{cp:int,char:string,count:int,name:string}>
     */
    public function audit(string $s): array
    {
        $re = '/[^\x{09}\x{0A}\x{0D}\x{20}-\x{7E}' . self::ALLOW[$this->profile] . ']/u';
        if (!preg_match_all($re, $s, $m)) { return []; }
        $found = [];
        foreach ($m[0] as $ch) {
            $cp = self::uord($ch);
            if (!isset($found[$cp])) {
                $found[$cp] = ['cp' => $cp, 'char' => $ch, 'count' => 0, 'name' => self::cpName($cp)];
            }
            $found[$cp]['count']++;
        }
        uasort($found, static fn($a, $b) => $b['count'] <=> $a['count'] ?: $a['cp'] <=> $b['cp']);
        return array_values($found);
    }

    // ------------------------------------------------------------ hidden data

    /**
     * Two carriers can hold an arbitrary payload and are decoded here:
     *  - variation selectors (FE00-FE0F = byte 0..15, E0100-E01EF = byte 16..255)
     *  - Unicode tag characters (E0020-E007E = ASCII 0x20-0x7E)
     * Zero width runs are decoded best effort as binary (ZWSP=0, ZWNJ=1).
     */
    private function decodeHidden(string $s): void
    {
        if (preg_match_all('/[\x{FE00}-\x{FE0F}\x{E0100}-\x{E01EF}]{4,}/u', $s, $m)) {
            foreach ($m[0] as $run) {
                $bytes = '';
                foreach ($this->chars($run) as $ch) {
                    $cp = self::uord($ch);
                    $bytes .= chr($cp <= 0xFE0F ? $cp - 0xFE00 : $cp - 0xE0100 + 16);
                }
                $this->hidden[] = ['type' => 'variation selectors', 'payload' => $bytes];
            }
        }
        if (preg_match_all('/[\x{E0001}\x{E0020}-\x{E007F}]{2,}/u', $s, $m)) {
            foreach ($m[0] as $run) {
                $txt = '';
                foreach ($this->chars($run) as $ch) {
                    $cp = self::uord($ch);
                    if ($cp >= 0xE0020 && $cp <= 0xE007E) { $txt .= chr($cp - 0xE0000); }
                }
                if ($txt !== '') { $this->hidden[] = ['type' => 'tag characters', 'payload' => $txt]; }
            }
        }
        if (preg_match_all('/[\x{200B}\x{200C}\x{200D}\x{FEFF}]{8,}/u', $s, $m)) {
            foreach ($m[0] as $run) {
                $bits = '';
                foreach ($this->chars($run) as $ch) {
                    $cp = self::uord($ch);
                    if ($cp === 0x200B) { $bits .= '0'; }
                    elseif ($cp === 0x200C) { $bits .= '1'; }
                }
                if (strlen($bits) >= 8) {
                    $txt = '';
                    foreach (str_split(substr($bits, 0, intdiv(strlen($bits), 8) * 8), 8) as $b) {
                        $txt .= chr((int)bindec($b));
                    }
                    $this->hidden[] = ['type' => 'zero width binary', 'payload' => $txt];
                }
            }
        }
    }

    // ------------------------------------------------------------------ rules

    private function nfc(string $s): string
    {
        if (class_exists('Normalizer')) {
            $n = \Normalizer::normalize($s, \Normalizer::FORM_C);
            if (is_string($n) && $n !== $s) { $this->log('nfc', 1); return $n; }
            return $s;
        }
        static $map = [
            "a\u{0301}" => 'á', "e\u{0301}" => 'é', "i\u{0301}" => 'í', "o\u{0301}" => 'ó',
            "u\u{0301}" => 'ú', "y\u{0301}" => 'ý', "n\u{0303}" => 'ñ', "a\u{0308}" => 'ä',
            "o\u{0308}" => 'ö', "u\u{0308}" => 'ü', "c\u{030C}" => 'č', "d\u{030C}" => 'ď',
            "e\u{030C}" => 'ě', "n\u{030C}" => 'ň', "r\u{030C}" => 'ř', "s\u{030C}" => 'š',
            "t\u{030C}" => 'ť', "z\u{030C}" => 'ž', "u\u{030A}" => 'ů',
        ];
        return $this->replaceMap($s, $map, 'nfc');
    }

    private function invisible(string $s): string
    {
        // soft hyphen, CGJ, ALM, Hangul fillers, Mongolian FVS, zero widths,
        // bidi embedding/override/isolates, word joiner, invisible math operators,
        // deprecated format chars, BOM, interlinear annotation, musical controls,
        // the Unicode tag block and the braille blank.
        $re = '/[\x{00AD}\x{034F}\x{061C}\x{115F}\x{1160}\x{17B4}\x{17B5}\x{180B}-\x{180F}'
            . '\x{200B}-\x{200F}\x{202A}-\x{202E}\x{2060}-\x{2064}\x{2066}-\x{206F}\x{2800}'
            . '\x{3164}\x{FEFF}\x{FFA0}\x{FFF9}-\x{FFFC}\x{1D173}-\x{1D17A}'
            . '\x{E0000}-\x{E007F}]/u';
        return $this->sub($s, $re, '', 'invisible');
    }

    private function varsel(string $s): string
    {
        $keep = [];
        if ($this->opt['keep_emoji']) {
            $emoji = '\x{00A9}\x{00AE}\x{203C}\x{2049}\x{2100}-\x{27BF}\x{2B00}-\x{2BFF}'
                   . '\x{1F000}-\x{1FAFF}\x{20E3}0-9#*';
            $keep[] = '(?<=[' . $emoji . '])\x{FE0F}';
        }
        if ($this->opt['keep_ivs']) {
            // Ideographic Variation Sequences are legitimate in CJK text.
            $keep[] = '(?<=[\x{3400}-\x{4DBF}\x{4E00}-\x{9FFF}\x{F900}-\x{FAFF}])[\x{E0100}-\x{E01EF}]';
        }
        $token = "\x01KEEPVS\x01";
        $marks = [];
        if ($keep) {
            $s = preg_replace_callback('/' . implode('|', $keep) . '/u', function ($m) use (&$marks, $token) {
                $marks[] = $m[0];
                return $token;
            }, $s) ?? $s;
        }
        $s = $this->sub($s, '/[\x{FE00}-\x{FE0F}\x{E0100}-\x{E01EF}]/u', '', 'varsel');
        foreach ($marks as $mk) {
            $s = preg_replace('/' . preg_quote($token, '/') . '/', $mk, $s, 1) ?? $s;
        }
        return $s;
    }

    private function spaces(string $s): string
    {
        $s = $this->sub($s, '/[\x{2028}\x{2029}]/u', "\n", 'linesep');
        $s = $this->sub($s, '/[\x{00A0}\x{202F}]/u', ' ', 'nbsp');
        $ideo = $this->profile === 'ja' ? '' : '\x{3000}';
        $s = $this->sub($s, '/[\x{2000}-\x{200A}\x{205F}\x{1680}' . $ideo . ']/u', ' ', 'typo_spaces');
        return $s;
    }

    private function fullwidth(string $s): string
    {
        return preg_replace_callback('/[\x{FF01}-\x{FF5E}]/u', function ($m) {
            $this->log('fullwidth', 1);
            return chr(self::uord($m[0]) - 0xFEE0);
        }, $s) ?? $s;
    }

    private function mathAlnum(string $s): string
    {
        return $this->replaceMap($s, self::mathMap(), 'mathalnum');
    }

    private function ligatures(string $s): string
    {
        static $map = ['ﬀ' => 'ff', 'ﬁ' => 'fi', 'ﬂ' => 'fl', 'ﬃ' => 'ffi', 'ﬄ' => 'ffl',
                       'ﬅ' => 'st', 'ﬆ' => 'st', 'Ĳ' => 'IJ', 'ĳ' => 'ij', 'ǅ' => 'Dz', 'ǆ' => 'dz'];
        return $this->replaceMap($s, $map, 'ligatures');
    }

    private function quotes(string $s): string
    {
        static $dbl = ['“', '”', '„', '‟', '❝', '❞', '〝', '〞', '〟', '＂', '″', '‶'];
        static $sgl = ['‘', '’', '‚', '‛', '❛', '❜', '′', '‵', 'ʼ', 'ʻ', 'ʽ', 'ʹ',
                       'ˈ', 'ˊ', 'ˋ', '´', '＇', '՚', '᾿'];
        $s = $this->replaceMap($s, array_fill_keys($dbl, '"'), 'dquotes');
        $s = $this->replaceMap($s, array_fill_keys($sgl, "'"), 'squotes');
        return $s;
    }

    private function guillemets(string $s): string
    {
        return $this->replaceMap($s, ['«' => '"', '»' => '"', '‹' => "'", '›' => "'"], 'guillemets');
    }

    private function dashes(string $s): string
    {
        // U+2015 doubles as a legitimate Japanese dash, so the ja profile keeps it.
        $bar = $this->profile === 'ja' ? '' : '\x{2015}';
        $d   = '\x{2010}\x{2011}\x{2012}\x{2013}\x{2014}' . $bar . '\x{2043}\x{2212}\x{02D7}\x{FE58}\x{FE63}';
        // number ranges stay tight: 2010-2020, 10-15 %
        $s = $this->sub($s, '/(\d)\h?[' . $d . ']\h?(\d)/u', '$1-$2', 'dashes');
        // word internal hyphen variants stay tight: e-mail, Baden-Wuerttemberg
        $s = $this->sub($s, '/(?<=\p{L})[\x{2010}\x{2011}\x{2012}\x{2013}\x{2043}\x{2212}\x{02D7}](?=\p{L})/u',
                        '-', 'dashes');
        // everything else becomes a spaced ASCII hyphen
        $s = $this->sub($s, '/\h*[' . $d . ']\h*/u', ' - ', 'dashes');
        // a dash opening a line is a list bullet
        $s = $this->sub($s, '/^ - /mu', '- ', 'dashes', false);
        return $s;
    }

    private function punct(string $s): string
    {
        $s = $this->sub($s, '/\x{2026}/u', '...', 'ellipsis');
        $s = $this->sub($s, '/\x{2025}/u', '..', 'ellipsis');
        $s = $this->sub($s, '/\x{203C}/u', '!!', 'punct_misc');
        $s = $this->sub($s, '/\x{2047}/u', '??', 'punct_misc');
        $s = $this->sub($s, '/\x{2048}/u', '?!', 'punct_misc');
        $s = $this->sub($s, '/\x{2049}/u', '!?', 'punct_misc');
        $s = $this->sub($s, '/^(\h*)[\x{2022}\x{2023}\x{2043}\x{25AA}\x{25CF}\x{25E6}\x{2219}\x{00B7}\x{2027}]\h+/mu',
                        '$1- ', 'bullets');
        $s = $this->sub($s, '/[\x{2022}\x{2023}\x{25AA}\x{25CF}\x{25E6}]/u', '-', 'bullets');
        $s = $this->sub($s, '/\x{00A0}?\x{2044}\x{00A0}?/u', '/', 'punct_misc');
        $s = $this->sub($s, '/[\x{2215}\x{2216}]/u', '/', 'punct_misc');
        $s = $this->sub($s, '/\x{2116}/u', 'No.', 'punct_misc');
        $s = $this->sub($s, '/[\x{2105}\x{2100}]/u', 'c/o', 'punct_misc');
        return $s;
    }

    private function symbols(string $s): string
    {
        static $map = [
            '×' => 'x', '·' => '*', '∙' => '*', '÷' => '/', '−' => '-', '±' => '+/-',
            '≤' => '<=', '≥' => '>=', '≠' => '!=', '≈' => '~', '≡' => '==',
            '→' => '->', '←' => '<-', '↔' => '<->', '⇒' => '=>', '⇐' => '<=', '⇔' => '<=>',
            '⟶' => '->', '⟵' => '<-', '⟹' => '=>', '↦' => '->', '™' => '(TM)', '℠' => '(SM)',
        ];
        return $this->replaceMap($s, $map, 'symbols');
    }

    private function homoglyphs(string $s): string
    {
        $map = self::homoglyphMap();
        return preg_replace_callback('/[\p{L}\p{M}\p{N}]+/u', function ($m) use ($map) {
            $word = $m[0];
            // only touch words that are already partly Latin, so genuine
            // Cyrillic or Greek text passes through untouched
            if (!preg_match('/[a-zA-Z]/', $word)) { return $word; }
            $out = '';
            $hit = 0;
            foreach ($this->chars($word) as $ch) {
                if (isset($map[$ch])) { $out .= $map[$ch]; $hit++; }
                else { $out .= $ch; }
            }
            if ($hit) { $this->log('homoglyph', $hit); }
            return $out;
        }, $s) ?? $s;
    }

    private function tidy(string $s): string
    {
        $s = $this->sub($s, "/\r\n?/", "\n", 'crlf');
        $s = $this->sub($s, '/[ \t]+$/m', '', 'trailing_ws');
        $s = $this->sub($s, '/(?<=\S) {2,}(?=\S)/', ' ', 'multi_space');
        $s = $this->sub($s, '/ +([,.;:!?])(?=\s|$)/u', '$1', 'space_before_punct');
        $s = $this->sub($s, '/\n{3,}/', "\n\n", 'blank_lines');
        return rtrim($s, "\n") . "\n";
    }

    // ---------------------------------------------------------------- helpers

    private function sub(string $s, string $re, string $rep, string $key, bool $count = true): string
    {
        $out = preg_replace($re, $rep, $s, -1, $n);
        if ($out === null) { return $s; }
        if ($count && $n) { $this->log($key, $n); }
        return $out;
    }

    private function replaceMap(string $s, array $map, string $key): string
    {
        if (!$map) { return $s; }
        $n = 0;
        $out = str_replace(array_keys($map), array_values($map), $s, $n);
        if ($n) { $this->log($key, $n); }
        return $out;
    }

    private function log(string $key, int $n): void
    {
        $this->report[$key] = ($this->report[$key] ?? 0) + $n;
    }

    /** @return array<int,string> */
    private function chars(string $s): array
    {
        return preg_split('//u', $s, -1, PREG_SPLIT_NO_EMPTY) ?: [];
    }

    /** UTF-8 codepoint of one character, pure PHP, no mbstring needed. */
    private static function uord(string $ch): int
    {
        $b = unpack('C*', $ch);
        if (!$b) { return 0; }
        $b = array_values($b);
        switch (count($b)) {
            case 1: return $b[0];
            case 2: return (($b[0] & 0x1F) << 6) | ($b[1] & 0x3F);
            case 3: return (($b[0] & 0x0F) << 12) | (($b[1] & 0x3F) << 6) | ($b[2] & 0x3F);
            case 4: return (($b[0] & 0x07) << 18) | (($b[1] & 0x3F) << 12)
                         | (($b[2] & 0x3F) << 6) | ($b[3] & 0x3F);
        }
        return 0;
    }

    /** UTF-8 encode one codepoint, pure PHP. */
    private static function uchr(int $cp): string
    {
        if ($cp < 0x80)    { return chr($cp); }
        if ($cp < 0x800)   { return chr(0xC0 | $cp >> 6) . chr(0x80 | $cp & 0x3F); }
        if ($cp < 0x10000) { return chr(0xE0 | $cp >> 12) . chr(0x80 | ($cp >> 6) & 0x3F)
                                  . chr(0x80 | $cp & 0x3F); }
        return chr(0xF0 | $cp >> 18) . chr(0x80 | ($cp >> 12) & 0x3F)
             . chr(0x80 | ($cp >> 6) & 0x3F) . chr(0x80 | $cp & 0x3F);
    }

    public static function ulen(string $s): int
    {
        return (int)preg_match_all('/./us', $s);
    }

    private static function cpName(int $cp): string
    {
        if (class_exists('IntlChar')) {
            $n = \IntlChar::charName($cp);
            if (is_string($n) && $n !== '') { return $n; }
        }
        return '';
    }

    private static function mathMap(): array
    {
        static $map = null;
        if ($map !== null) { return $map; }
        $map = [];
        $ranges = [
            [0x1D400, 'A', 26], [0x1D41A, 'a', 26], [0x1D434, 'A', 26], [0x1D44E, 'a', 26],
            [0x1D468, 'A', 26], [0x1D482, 'a', 26], [0x1D49C, 'A', 26], [0x1D4B6, 'a', 26],
            [0x1D4D0, 'A', 26], [0x1D4EA, 'a', 26], [0x1D504, 'A', 26], [0x1D51E, 'a', 26],
            [0x1D538, 'A', 26], [0x1D552, 'a', 26], [0x1D56C, 'A', 26], [0x1D586, 'a', 26],
            [0x1D5A0, 'A', 26], [0x1D5BA, 'a', 26], [0x1D5D4, 'A', 26], [0x1D5EE, 'a', 26],
            [0x1D608, 'A', 26], [0x1D622, 'a', 26], [0x1D63C, 'A', 26], [0x1D656, 'a', 26],
            [0x1D670, 'A', 26], [0x1D68A, 'a', 26],
            [0x1D7CE, '0', 10], [0x1D7D8, '0', 10], [0x1D7E2, '0', 10], [0x1D7EC, '0', 10],
            [0x1D7F6, '0', 10],
        ];
        foreach ($ranges as [$start, $base, $len]) {
            for ($i = 0; $i < $len; $i++) {
                $map[self::uchr($start + $i)] = chr(ord($base) + $i);
            }
        }
        // letterlike symbols filling the holes in the math block
        $extra = [
            0x2102 => 'C', 0x210A => 'g', 0x210B => 'H', 0x210C => 'H', 0x210D => 'H', 0x210E => 'h',
            0x2110 => 'I', 0x2111 => 'I', 0x2112 => 'L', 0x2113 => 'l', 0x2115 => 'N', 0x2119 => 'P',
            0x211A => 'Q', 0x211B => 'R', 0x211C => 'R', 0x211D => 'R', 0x2124 => 'Z', 0x2128 => 'Z',
            0x212A => 'K', 0x212C => 'B', 0x212D => 'C', 0x212F => 'e', 0x2130 => 'E', 0x2131 => 'F',
            0x2133 => 'M', 0x2134 => 'o', 0x213C => 'p', 0x213D => 'y', 0x213E => 'G', 0x213F => 'P',
            0x2145 => 'D', 0x2146 => 'd', 0x2147 => 'e', 0x2148 => 'i', 0x2149 => 'j',
        ];
        foreach ($extra as $cp => $ascii) { $map[self::uchr($cp)] = $ascii; }
        $map[self::uchr(0x212B)] = 'Å';
        return $map;
    }

    private static function homoglyphMap(): array
    {
        static $map = null;
        if ($map !== null) { return $map; }
        $map = [
            'А' => 'A', 'В' => 'B', 'Е' => 'E', 'К' => 'K', 'М' => 'M', 'Н' => 'H', 'О' => 'O',
            'Р' => 'P', 'С' => 'C', 'Т' => 'T', 'У' => 'Y', 'Х' => 'X', 'І' => 'I', 'Ј' => 'J',
            'Ѕ' => 'S', 'Ԛ' => 'Q', 'Ԝ' => 'W', 'Ү' => 'Y', 'Ғ' => 'F',
            'а' => 'a', 'е' => 'e', 'о' => 'o', 'р' => 'p', 'с' => 'c', 'у' => 'y', 'х' => 'x',
            'і' => 'i', 'ј' => 'j', 'ѕ' => 's', 'ԁ' => 'd', 'һ' => 'h', 'ӏ' => 'l', 'ѵ' => 'v',
            'Α' => 'A', 'Β' => 'B', 'Ε' => 'E', 'Ζ' => 'Z', 'Η' => 'H', 'Ι' => 'I', 'Κ' => 'K',
            'Μ' => 'M', 'Ν' => 'N', 'Ο' => 'O', 'Ρ' => 'P', 'Τ' => 'T', 'Υ' => 'Y', 'Χ' => 'X',
            'ο' => 'o', 'ρ' => 'p', 'ν' => 'v', 'ϲ' => 'c', 'ϳ' => 'j',
            'ı' => 'i', 'ȷ' => 'j', 'ǀ' => '|', 'ǃ' => '!', 'ɑ' => 'a', 'ɡ' => 'g', 'ɩ' => 'i',
            'ᴀ' => 'A', 'ᴄ' => 'C', 'ᴅ' => 'D', 'ᴇ' => 'E', 'ᴏ' => 'O', 'ᴘ' => 'P', 'ᴛ' => 'T',
            'օ' => 'o', 'ո' => 'n', 'ս' => 'u', 'ց' => 'g', 'ɓ' => 'b',
        ];
        return $map;
    }
}

/* ------------------------------------------------------------------- i18n */

final class I18n
{
    public const LANGS = ['en' => 'English', 'de' => 'Deutsch', 'es' => 'Español',
                          'cs' => 'Čeština', 'ja' => '日本語'];

    private const S = [
'en' => [
 'tagline' => 'Removes invisible characters, steganographic carriers and typographic artifacts from LLM output. The wording stays exactly the same. Nothing is stored or sent anywhere.',
 'input' => 'Input', 'output' => 'Output', 'rules' => 'Rules', 'profile' => 'Text profile',
 'uilang' => 'Interface', 'run' => 'Clean', 'copy' => 'Copy output', 'chars' => 'characters',
 'steg_title' => 'Hidden payload found', 'steg_text' => 'text', 'steg_hex' => 'hex',
 'rep_title' => 'What changed', 'rep_rule' => 'rule', 'rep_count' => 'count',
 'rep_clean' => 'Nothing. The text was already clean.',
 'audit_title' => 'Left outside the keyboard', 'audit_char' => 'char', 'audit_code' => 'code',
 'audit_name' => 'name', 'audit_clean' => 'Nothing. Everything is on the keyboard.',
 'note' => 'Character level cleaning cannot remove a statistical watermark such as SynthID or a green list scheme, because that is encoded in the choice of tokens, not in the characters. Only rewriting the text removes it.',
 'placeholder' => 'Paste text here...',
 'o_hidden' => 'Decode hidden payloads', 'o_invisible' => 'Invisible characters (ZWSP, ZWJ, BOM, bidi, tags)',
 'o_varsel' => 'Variation selectors (FE00-FE0F, E0100-E01EF)', 'o_keep_emoji' => '... but keep VS16 after emoji',
 'o_keep_ivs' => '... but keep IVS after kanji', 'o_spaces' => 'Non-breaking and typographic spaces',
 'o_dashes' => 'Em and en dashes to hyphen', 'o_quotes' => 'Curly quotes and apostrophes to straight',
 'o_guillemets' => 'Guillemets to straight quotes', 'o_punct' => 'Ellipsis, bullets, numero',
 'o_symbols' => 'Arrows, x, <=, >=, !=', 'o_fullwidth' => 'Fullwidth forms to ASCII',
 'o_mathalnum' => 'Mathematical alphanumerics to ASCII', 'o_ligatures' => 'Ligatures fi fl ff',
 'o_homoglyph' => 'Cyrillic and Greek lookalikes in Latin words', 'o_nfc' => 'Recompose decomposed diacritics (NFC)',
 'o_tidy' => 'Whitespace and line ending cleanup',
 'r_broken_utf8' => 'malformed UTF-8', 'r_nfc' => 'decomposed diacritics', 'r_invisible' => 'invisible controls',
 'r_varsel' => 'variation selectors', 'r_linesep' => 'line/paragraph separators', 'r_nbsp' => 'non-breaking spaces',
 'r_typo_spaces' => 'typographic spaces', 'r_fullwidth' => 'fullwidth forms', 'r_mathalnum' => 'math alphanumerics',
 'r_ligatures' => 'ligatures', 'r_dquotes' => 'curly double quotes', 'r_squotes' => 'curly single quotes',
 'r_guillemets' => 'guillemets', 'r_dashes' => 'long dashes', 'r_ellipsis' => 'ellipsis',
 'r_bullets' => 'bullets', 'r_punct_misc' => 'other punctuation', 'r_symbols' => 'symbol replacements',
 'r_homoglyph' => 'homoglyphs', 'r_crlf' => 'CRLF line endings', 'r_trailing_ws' => 'trailing whitespace',
 'r_multi_space' => 'repeated spaces', 'r_space_before_punct' => 'space before punctuation',
 'r_blank_lines' => 'extra blank lines',
],
'de' => [
 'tagline' => 'Entfernt unsichtbare Zeichen, steganografische Träger und typografische Artefakte aus LLM-Text. Der Wortlaut bleibt unverändert. Nichts wird gespeichert oder übertragen.',
 'input' => 'Eingabe', 'output' => 'Ausgabe', 'rules' => 'Regeln', 'profile' => 'Textprofil',
 'uilang' => 'Oberfläche', 'run' => 'Bereinigen', 'copy' => 'Ausgabe kopieren', 'chars' => 'Zeichen',
 'steg_title' => 'Versteckte Nutzlast gefunden', 'steg_text' => 'Text', 'steg_hex' => 'Hex',
 'rep_title' => 'Was geändert wurde', 'rep_rule' => 'Regel', 'rep_count' => 'Anzahl',
 'rep_clean' => 'Nichts. Der Text war bereits sauber.',
 'audit_title' => 'Nicht auf der Tastatur verblieben', 'audit_char' => 'Zeichen', 'audit_code' => 'Code',
 'audit_name' => 'Name', 'audit_clean' => 'Nichts. Alles liegt auf der Tastatur.',
 'note' => 'Eine Zeichenbereinigung entfernt kein statistisches Wasserzeichen wie SynthID oder ein Green-List-Verfahren, denn das steckt in der Tokenwahl, nicht in den Zeichen. Dagegen hilft nur ein Umschreiben des Textes.',
 'placeholder' => 'Text hier einfügen...',
 'o_hidden' => 'Versteckte Nutzlasten dekodieren', 'o_invisible' => 'Unsichtbare Zeichen (ZWSP, ZWJ, BOM, Bidi, Tags)',
 'o_varsel' => 'Variantenselektoren (FE00-FE0F, E0100-E01EF)', 'o_keep_emoji' => '... VS16 nach Emoji behalten',
 'o_keep_ivs' => '... IVS nach Kanji behalten', 'o_spaces' => 'Geschützte und typografische Leerzeichen',
 'o_dashes' => 'Geviert- und Halbgeviertstrich zu Bindestrich', 'o_quotes' => 'Typografische Anführungszeichen zu geraden',
 'o_guillemets' => 'Guillemets zu geraden Anführungszeichen', 'o_punct' => 'Auslassungspunkte, Aufzählungszeichen, Numero',
 'o_symbols' => 'Pfeile, x, <=, >=, !=', 'o_fullwidth' => 'Vollbreite Zeichen zu ASCII',
 'o_mathalnum' => 'Mathematische Alphanumerik zu ASCII', 'o_ligatures' => 'Ligaturen fi fl ff',
 'o_homoglyph' => 'Kyrillische und griechische Doppelgänger in lateinischen Wörtern',
 'o_nfc' => 'Zerlegte Diakritika zusammensetzen (NFC)', 'o_tidy' => 'Leerraum und Zeilenenden aufräumen',
 'r_broken_utf8' => 'fehlerhaftes UTF-8', 'r_nfc' => 'zerlegte Diakritika', 'r_invisible' => 'unsichtbare Steuerzeichen',
 'r_varsel' => 'Variantenselektoren', 'r_linesep' => 'Zeilen- und Absatztrenner', 'r_nbsp' => 'geschützte Leerzeichen',
 'r_typo_spaces' => 'typografische Leerzeichen', 'r_fullwidth' => 'vollbreite Zeichen', 'r_mathalnum' => 'mathematische Alphanumerik',
 'r_ligatures' => 'Ligaturen', 'r_dquotes' => 'typografische Anführungszeichen', 'r_squotes' => 'typografische Apostrophe',
 'r_guillemets' => 'Guillemets', 'r_dashes' => 'lange Striche', 'r_ellipsis' => 'Auslassungspunkte',
 'r_bullets' => 'Aufzählungszeichen', 'r_punct_misc' => 'sonstige Interpunktion', 'r_symbols' => 'Symbolersetzungen',
 'r_homoglyph' => 'Homoglyphen', 'r_crlf' => 'CRLF-Zeilenenden', 'r_trailing_ws' => 'Leerzeichen am Zeilenende',
 'r_multi_space' => 'mehrfache Leerzeichen', 'r_space_before_punct' => 'Leerzeichen vor Interpunktion',
 'r_blank_lines' => 'überzählige Leerzeilen',
],
'es' => [
 'tagline' => 'Elimina caracteres invisibles, portadores esteganográficos y artefactos tipográficos del texto de un LLM. La redacción no cambia. No se guarda ni se envía nada.',
 'input' => 'Entrada', 'output' => 'Salida', 'rules' => 'Reglas', 'profile' => 'Perfil de texto',
 'uilang' => 'Interfaz', 'run' => 'Limpiar', 'copy' => 'Copiar salida', 'chars' => 'caracteres',
 'steg_title' => 'Carga oculta encontrada', 'steg_text' => 'texto', 'steg_hex' => 'hex',
 'rep_title' => 'Qué ha cambiado', 'rep_rule' => 'regla', 'rep_count' => 'total',
 'rep_clean' => 'Nada. El texto ya estaba limpio.',
 'audit_title' => 'Queda fuera del teclado', 'audit_char' => 'carácter', 'audit_code' => 'código',
 'audit_name' => 'nombre', 'audit_clean' => 'Nada. Todo está en el teclado.',
 'note' => 'La limpieza de caracteres no elimina una marca de agua estadística como SynthID o un esquema de lista verde, porque va codificada en la elección de tokens, no en los caracteres. Solo reescribir el texto la elimina.',
 'placeholder' => 'Pega el texto aquí...',
 'o_hidden' => 'Descodificar cargas ocultas', 'o_invisible' => 'Caracteres invisibles (ZWSP, ZWJ, BOM, bidi, tags)',
 'o_varsel' => 'Selectores de variación (FE00-FE0F, E0100-E01EF)', 'o_keep_emoji' => '... pero conservar VS16 tras emoji',
 'o_keep_ivs' => '... pero conservar IVS tras kanji', 'o_spaces' => 'Espacios duros y tipográficos',
 'o_dashes' => 'Rayas y semirrayas a guion', 'o_quotes' => 'Comillas y apóstrofos tipográficos a rectos',
 'o_guillemets' => 'Comillas angulares a rectas', 'o_punct' => 'Puntos suspensivos, viñetas, numero',
 'o_symbols' => 'Flechas, x, <=, >=, !=', 'o_fullwidth' => 'Formas de ancho completo a ASCII',
 'o_mathalnum' => 'Alfanuméricos matemáticos a ASCII', 'o_ligatures' => 'Ligaduras fi fl ff',
 'o_homoglyph' => 'Homóglifos cirílicos y griegos en palabras latinas',
 'o_nfc' => 'Recomponer diacríticos descompuestos (NFC)', 'o_tidy' => 'Limpieza de espacios y fin de línea',
 'r_broken_utf8' => 'UTF-8 mal formado', 'r_nfc' => 'diacríticos descompuestos', 'r_invisible' => 'controles invisibles',
 'r_varsel' => 'selectores de variación', 'r_linesep' => 'separadores de línea y párrafo', 'r_nbsp' => 'espacios duros',
 'r_typo_spaces' => 'espacios tipográficos', 'r_fullwidth' => 'formas de ancho completo', 'r_mathalnum' => 'alfanuméricos matemáticos',
 'r_ligatures' => 'ligaduras', 'r_dquotes' => 'comillas dobles curvas', 'r_squotes' => 'comillas simples curvas',
 'r_guillemets' => 'comillas angulares', 'r_dashes' => 'rayas largas', 'r_ellipsis' => 'puntos suspensivos',
 'r_bullets' => 'viñetas', 'r_punct_misc' => 'otra puntuación', 'r_symbols' => 'sustituciones de símbolos',
 'r_homoglyph' => 'homóglifos', 'r_crlf' => 'fin de línea CRLF', 'r_trailing_ws' => 'espacios finales',
 'r_multi_space' => 'espacios repetidos', 'r_space_before_punct' => 'espacio antes de puntuación',
 'r_blank_lines' => 'líneas en blanco de más',
],
'cs' => [
 'tagline' => 'Odstrani z textu neviditelne nosice, steganograficke znaky a typograficke artefakty z LLM. Obsah textu zustava stejny. Nic se neuklada ani neodesila.',
 'input' => 'Vstup', 'output' => 'Vystup', 'rules' => 'Pravidla', 'profile' => 'Profil textu',
 'uilang' => 'Rozhrani', 'run' => 'Vycistit', 'copy' => 'Kopirovat vystup', 'chars' => 'znaku',
 'steg_title' => 'Nalezen skryty obsah', 'steg_text' => 'text', 'steg_hex' => 'hex',
 'rep_title' => 'Co se zmenilo', 'rep_rule' => 'pravidlo', 'rep_count' => 'pocet',
 'rep_clean' => 'Nic. Text byl cisty.',
 'audit_title' => 'Zbyva mimo klavesnici', 'audit_char' => 'znak', 'audit_code' => 'kod',
 'audit_name' => 'nazev', 'audit_clean' => 'Nic. Vsechno je na klavesnici.',
 'note' => 'Cisteni znaku neodstrani statisticky watermark typu SynthID nebo green list. Ten je zakodovany ve volbe tokenu, ne ve znacich. Proti tomu pomaha jen prepis textu.',
 'placeholder' => 'Sem vloz text...',
 'o_hidden' => 'Dekodovat skryte payloady', 'o_invisible' => 'Neviditelne znaky (ZWSP, ZWJ, BOM, bidi, tagy)',
 'o_varsel' => 'Variation selectors (FE00-FE0F, E0100-E01EF)', 'o_keep_emoji' => '... ale nechat VS16 u emoji',
 'o_keep_ivs' => '... ale nechat IVS za kandzi', 'o_spaces' => 'Pevne a typograficke mezery',
 'o_dashes' => 'Dlouhe pomlcky na spojovnik', 'o_quotes' => 'Kudrnate uvozovky a apostrofy na rovne',
 'o_guillemets' => 'Guillemety na rovne uvozovky', 'o_punct' => 'Vypustka, odrazky, numero',
 'o_symbols' => 'Sipky, x, <=, >=, !=', 'o_fullwidth' => 'Fullwidth znaky na ASCII',
 'o_mathalnum' => 'Matematicke alfanumericke znaky na ASCII', 'o_ligatures' => 'Ligatury fi fl ff',
 'o_homoglyph' => 'Cyrilske a recke homoglyfy v latinskych slovech',
 'o_nfc' => 'Slozit rozlozenou diakritiku (NFC)', 'o_tidy' => 'Uklid bilych znaku a koncu radku',
 'r_broken_utf8' => 'poskozene UTF-8', 'r_nfc' => 'rozlozena diakritika', 'r_invisible' => 'neviditelne ridici znaky',
 'r_varsel' => 'variation selectors', 'r_linesep' => 'oddelovace radku a odstavcu', 'r_nbsp' => 'pevne mezery',
 'r_typo_spaces' => 'typograficke mezery', 'r_fullwidth' => 'fullwidth znaky', 'r_mathalnum' => 'matematicke alfanumericke znaky',
 'r_ligatures' => 'ligatury', 'r_dquotes' => 'kudrnate dvojite uvozovky', 'r_squotes' => 'kudrnate jednoduche uvozovky',
 'r_guillemets' => 'guillemety', 'r_dashes' => 'dlouhe pomlcky', 'r_ellipsis' => 'vypustka',
 'r_bullets' => 'odrazky', 'r_punct_misc' => 'ostatni interpunkce', 'r_symbols' => 'symbolove nahrady',
 'r_homoglyph' => 'homoglyfy', 'r_crlf' => 'CRLF konce radku', 'r_trailing_ws' => 'mezery na konci radku',
 'r_multi_space' => 'vicenasobne mezery', 'r_space_before_punct' => 'mezera pred interpunkci',
 'r_blank_lines' => 'prazdne radky navic',
],
'ja' => [
 'tagline' => 'LLM の出力から不可視文字、ステガノグラフィの担体、タイポグラフィ由来の痕跡を取り除きます。文章そのものは変わりません。データの保存も送信も行いません。',
 'input' => '入力', 'output' => '出力', 'rules' => 'ルール', 'profile' => 'テキストのプロファイル',
 'uilang' => '表示言語', 'run' => 'クリーンアップ', 'copy' => '出力をコピー', 'chars' => '文字',
 'steg_title' => '隠しデータを検出しました', 'steg_text' => 'テキスト', 'steg_hex' => '16進',
 'rep_title' => '変更内容', 'rep_rule' => 'ルール', 'rep_count' => '件数',
 'rep_clean' => '変更はありません。テキストはすでにクリーンでした。',
 'audit_title' => 'キーボード外に残った文字', 'audit_char' => '文字', 'audit_code' => 'コード',
 'audit_name' => '名称', 'audit_clean' => '残っている文字はありません。',
 'note' => '文字レベルの洗浄では SynthID などの統計的な電子透かしは除去できません。あれは文字ではなくトークンの選択に埋め込まれているためです。取り除くには文章そのものを書き換える必要があります。',
 'placeholder' => 'ここにテキストを貼り付けてください...',
 'o_hidden' => '隠しデータをデコードする', 'o_invisible' => '不可視文字 (ZWSP, ZWJ, BOM, bidi, タグ)',
 'o_varsel' => '異体字セレクタ (FE00-FE0F, E0100-E01EF)', 'o_keep_emoji' => '... 絵文字直後の VS16 は残す',
 'o_keep_ivs' => '... 漢字直後の IVS は残す', 'o_spaces' => 'ノーブレークスペースと約物スペース',
 'o_dashes' => 'ダッシュ類をハイフンに', 'o_quotes' => '曲がった引用符をまっすぐに',
 'o_guillemets' => 'ギユメをまっすぐな引用符に', 'o_punct' => '三点リーダ、箇条書き記号、ナンバー記号',
 'o_symbols' => '矢印、x、<=、>=、!=', 'o_fullwidth' => '全角文字を ASCII に',
 'o_mathalnum' => '数学用英数字を ASCII に', 'o_ligatures' => '合字 fi fl ff',
 'o_homoglyph' => 'ラテン語中のキリル文字・ギリシャ文字の偽装',
 'o_nfc' => '分解された発音区別符号を合成 (NFC)', 'o_tidy' => '空白と改行コードの整理',
 'r_broken_utf8' => '不正な UTF-8', 'r_nfc' => '分解された発音区別符号', 'r_invisible' => '不可視制御文字',
 'r_varsel' => '異体字セレクタ', 'r_linesep' => '行・段落区切り', 'r_nbsp' => 'ノーブレークスペース',
 'r_typo_spaces' => '約物スペース', 'r_fullwidth' => '全角文字', 'r_mathalnum' => '数学用英数字',
 'r_ligatures' => '合字', 'r_dquotes' => '曲がった二重引用符', 'r_squotes' => '曲がった一重引用符',
 'r_guillemets' => 'ギユメ', 'r_dashes' => '長いダッシュ', 'r_ellipsis' => '三点リーダ',
 'r_bullets' => '箇条書き記号', 'r_punct_misc' => 'その他の約物', 'r_symbols' => '記号の置換',
 'r_homoglyph' => '偽装文字', 'r_crlf' => 'CRLF 改行', 'r_trailing_ws' => '行末の空白',
 'r_multi_space' => '連続する空白', 'r_space_before_punct' => '約物前の空白',
 'r_blank_lines' => '余分な空行',
],
    ];

    public static function t(string $lang, string $key): string
    {
        return self::S[$lang][$key] ?? self::S['en'][$key] ?? $key;
    }

    public static function detect(): string
    {
        if (isset($_GET['lang']) && isset(self::LANGS[(string)$_GET['lang']])) {
            return (string)$_GET['lang'];
        }
        if (isset($_COOKIE['lls_lang']) && isset(self::LANGS[(string)$_COOKIE['lls_lang']])) {
            return (string)$_COOKIE['lls_lang'];
        }
        $hdr = (string)($_SERVER['HTTP_ACCEPT_LANGUAGE'] ?? '');
        foreach (explode(',', $hdr) as $part) {
            $code = strtolower(trim(explode(';', $part)[0]));
            $code = str_replace(['cs-cz', 'cz'], 'cs', $code);
            $short = substr($code, 0, 2);
            if (isset(self::LANGS[$short])) { return $short; }
        }
        return 'en';
    }
}

/* -------------------------------------------------------------------- CLI */

if (PHP_SAPI === 'cli') {
    /** Pad to a display width, counting CJK/fullwidth glyphs as two columns. */
    function cli_pad(string $str, int $width): string
    {
        $w = 0;
        foreach (preg_split('//u', $str, -1, PREG_SPLIT_NO_EMPTY) ?: [] as $ch) {
            $w += preg_match('/[\x{1100}-\x{115F}\x{2E80}-\x{A4CF}\x{AC00}-\x{D7A3}'
                . '\x{F900}-\x{FAFF}\x{FE30}-\x{FE6F}\x{FF00}-\x{FF60}\x{FFE0}-\x{FFE6}]/u', $ch) ? 2 : 1;
        }
        return $str . str_repeat(' ', max(1, $width - $w));
    }

    $opts = [];
    $profile = 'en';
    $lang = 'en';
    $reportOnly = false;
    foreach (array_slice($argv, 1) as $a) {
        if ($a === '--report') { $reportOnly = true; }
        elseif (strpos($a, '--profile=') === 0) { $profile = substr($a, 10); }
        elseif (strpos($a, '--lang=') === 0) { $lang = substr($a, 7); }
        elseif ($a === '--version') { echo 'LLM Sanitizer ' . LlmSanitizer::VERSION . " (MIT)\n"; exit(0); }
        elseif ($a === '--help' || $a === '-h') {
            fwrite(STDERR, "LLM Sanitizer " . LlmSanitizer::VERSION . " - MIT\n"
                . "usage: php llm-sanitizer.php [--profile=en|de|es|cs|ja|universal] [--lang=xx]\n"
                . "       [--report] [--no-RULE ...] [--RULE ...] < in.txt > out.txt\n"
                . "rules: " . implode(', ', array_keys(LlmSanitizer::DEFAULTS)) . "\n");
            exit(0);
        }
        elseif (strpos($a, '--no-') === 0) { $opts[substr($a, 5)] = false; }
        elseif (strpos($a, '--') === 0) { $opts[substr($a, 2)] = true; }
    }
    if (!isset(I18n::LANGS[$lang])) { $lang = 'en'; }
    $s = new LlmSanitizer($opts, $profile);
    $out = $s->run((string)stream_get_contents(STDIN));
    if (!$reportOnly) { echo $out; }
    foreach ($s->report() as $k => $v) {
        fwrite(STDERR, cli_pad(I18n::t($lang, 'r_' . $k), 42) . ' ' . $v . "\n");
    }
    foreach ($s->hidden() as $h) {
        fwrite(STDERR, I18n::t($lang, 'steg_title') . " [{$h['type']}]: "
            . addcslashes($h['payload'], "\0..\37\177..\377") . "\n");
    }
    foreach ($s->audit($out) as $r) {
        fwrite(STDERR, sprintf("U+%04X %-40s x%d\n", $r['cp'], $r['name'], $r['count']));
    }
    exit(0);
}

/* -------------------------------------------------------------------- web */

$lang = I18n::detect();
if (isset($_POST['uilang']) && isset(I18n::LANGS[(string)$_POST['uilang']])) {
    $lang = (string)$_POST['uilang'];
}
if (!headers_sent()) {
    setcookie('lls_lang', $lang, ['expires' => time() + 31536000, 'path' => '/', 'samesite' => 'Lax']);
}

$posted   = ($_SERVER['REQUEST_METHOD'] ?? 'GET') === 'POST';
$profiles = array_keys(LlmSanitizer::PROFILE_OVERRIDES);
$profile  = $posted ? (string)($_POST['profile'] ?? $lang) : $lang;
if (!in_array($profile, $profiles, true)) { $profile = 'en'; }

$text = (string)($_POST['text'] ?? '');
$defs = LlmSanitizer::profileDefaults($profile);
$opts = [];
foreach ($defs as $k => $def) { $opts[$k] = $posted ? isset($_POST['opt'][$k]) : $def; }

$san    = new LlmSanitizer($opts, $profile);
$result = $posted ? $san->run($text) : '';
$report = $san->report();
$hidden = $san->hidden();
$rest   = $posted ? $san->audit($result) : [];

function h(?string $s): string { return htmlspecialchars((string)$s, ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8'); }
function t(string $k): string { global $lang; return I18n::t($lang, $k); }

$profileDefaultsJson = [];
foreach ($profiles as $p) { $profileDefaultsJson[$p] = LlmSanitizer::profileDefaults($p); }
$profileNames = ['en' => 'English', 'de' => 'Deutsch', 'es' => 'Español', 'cs' => 'Čeština',
                 'ja' => '日本語', 'universal' => 'Universal'];
?><!doctype html>
<html lang="<?= h($lang) ?>">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta name="robots" content="noindex,nofollow">
<title>LLM Sanitizer</title>
<style>
:root { color-scheme: dark; --bg:#12141a; --fg:#e6e8ee; --mut:#8b93a7; --acc:#7dd3a0;
        --warn:#e8a33d; --line:#262a35; --panel:#0c0e13 }
* { box-sizing:border-box }
body { margin:0; padding:24px; background:var(--bg); color:var(--fg);
       font:15px/1.55 ui-sans-serif,system-ui,"Segoe UI","Hiragino Sans","Noto Sans JP",Roboto,sans-serif }
.wrap { max-width:1180px; margin:0 auto }
header { display:flex; flex-wrap:wrap; align-items:baseline; gap:12px; justify-content:space-between }
h1 { font-size:20px; margin:0; letter-spacing:-.01em }
h1 span { color:var(--mut); font-weight:400; font-size:12px; margin-left:8px }
p.sub { color:var(--mut); margin:6px 0 18px; font-size:13px; max-width:80ch }
.cols { display:grid; grid-template-columns:1fr 1fr; gap:16px }
@media (max-width:900px){ .cols{grid-template-columns:1fr} }
textarea { width:100%; height:330px; padding:12px; background:var(--panel); color:var(--fg);
           border:1px solid var(--line); border-radius:8px; resize:vertical;
           font:13px/1.5 ui-monospace,"Cascadia Code",Consolas,"Noto Sans Mono CJK JP",monospace;
           white-space:pre-wrap }
select { background:var(--panel); color:var(--fg); border:1px solid var(--line);
         border-radius:6px; padding:5px 8px; font-size:13px }
fieldset { border:1px solid var(--line); border-radius:8px; margin:16px 0; padding:12px 14px }
legend { color:var(--mut); font-size:12px; text-transform:uppercase; letter-spacing:.08em; padding:0 6px }
.opts { display:grid; grid-template-columns:repeat(auto-fill,minmax(310px,1fr)); gap:4px 18px }
label.chk { display:flex; gap:8px; align-items:baseline; font-size:13px; cursor:pointer }
button { background:var(--acc); color:#0c0e13; border:0; border-radius:8px; padding:10px 20px;
         font-weight:600; cursor:pointer; font-size:14px }
button.ghost { background:transparent; color:var(--fg); border:1px solid var(--line); font-weight:500 }
.bar { display:flex; gap:10px; align-items:center; flex-wrap:wrap; margin:14px 0 }
.bar .sel { display:flex; gap:6px; align-items:center; font-size:12px; color:var(--mut) }
table { width:100%; border-collapse:collapse; font-size:13px; margin-top:4px }
td,th { text-align:left; padding:5px 8px; border-bottom:1px solid var(--line) }
th { color:var(--mut); font-weight:500; font-size:12px }
td.n { text-align:right; font-variant-numeric:tabular-nums; color:var(--acc); width:70px }
code { font:12px ui-monospace,Consolas,monospace; background:var(--panel); padding:1px 5px; border-radius:4px }
.steg { border:1px solid var(--warn); border-radius:8px; padding:10px 14px; margin:12px 0; background:#2a1f0c }
.steg h3 { margin:0 0 6px; font-size:14px; color:var(--warn) }
.steg div + div { margin-top:8px }
.mut { color:var(--mut) }
footer { margin-top:22px; font-size:12px; color:var(--mut); border-top:1px solid var(--line); padding-top:12px }
a { color:var(--acc) }
</style>
</head>
<body>
<div class="wrap">
<header>
  <h1>LLM Sanitizer <span>v<?= h(LlmSanitizer::VERSION) ?> &middot; MIT</span></h1>
  <form method="post" id="langform" class="sel">
    <input type="hidden" name="text" value="<?= h($text) ?>">
    <input type="hidden" name="profile" value="<?= h($profile) ?>">
    <label class="mut" for="uilang"><?= h(t('uilang')) ?></label>
    <select id="uilang" name="uilang" onchange="document.getElementById('langform').submit()">
      <?php foreach (I18n::LANGS as $code => $name): ?>
        <option value="<?= h($code) ?>" <?= $code === $lang ? 'selected' : '' ?>><?= h($name) ?></option>
      <?php endforeach; ?>
    </select>
  </form>
</header>
<p class="sub"><?= h(t('tagline')) ?></p>

<form method="post" id="main">
  <input type="hidden" name="uilang" value="<?= h($lang) ?>">
  <div class="cols">
    <div>
      <label class="mut" for="in"><?= h(t('input')) ?></label>
      <textarea id="in" name="text" placeholder="<?= h(t('placeholder')) ?>"><?= h($text) ?></textarea>
    </div>
    <div>
      <label class="mut" for="out"><?= h(t('output')) ?></label>
      <textarea id="out" readonly><?= h($result) ?></textarea>
    </div>
  </div>

  <fieldset>
    <legend><?= h(t('rules')) ?></legend>
    <div class="bar">
      <span class="sel">
        <label for="profile"><?= h(t('profile')) ?></label>
        <select id="profile" name="profile" onchange="applyProfile(this.value)">
          <?php foreach ($profiles as $p): ?>
            <option value="<?= h($p) ?>" <?= $p === $profile ? 'selected' : '' ?>><?= h($profileNames[$p]) ?></option>
          <?php endforeach; ?>
        </select>
      </span>
    </div>
    <div class="opts">
      <?php foreach ($defs as $k => $_): ?>
        <label class="chk"><input type="checkbox" name="opt[<?= h($k) ?>]" value="1"
          data-rule="<?= h($k) ?>" <?= $opts[$k] ? 'checked' : '' ?>><span><?= h(t('o_' . $k)) ?></span></label>
      <?php endforeach; ?>
    </div>
  </fieldset>

  <div class="bar">
    <button type="submit"><?= h(t('run')) ?></button>
    <button type="button" class="ghost"
      onclick="navigator.clipboard.writeText(document.getElementById('out').value)"><?= h(t('copy')) ?></button>
    <span class="mut" style="font-size:12px">
      <?= $posted ? h(LlmSanitizer::ulen($text) . ' -> ' . LlmSanitizer::ulen($result) . ' ' . t('chars')) : '' ?>
    </span>
  </div>
</form>

<?php if ($hidden): ?>
  <div class="steg">
    <h3><?= h(t('steg_title')) ?></h3>
    <?php foreach ($hidden as $hh): ?>
      <div>
        <strong><?= h($hh['type']) ?></strong><br>
        <?= h(t('steg_text')) ?>: <code><?= h((string)preg_replace('/[^\x20-\x7E]/', '.', $hh['payload'])) ?></code><br>
        <?= h(t('steg_hex')) ?>: <code><?= h(trim(chunk_split(strtoupper(bin2hex($hh['payload'])), 2, ' '))) ?></code>
      </div>
    <?php endforeach; ?>
  </div>
<?php endif; ?>

<?php if ($posted): ?>
<div class="cols">
  <fieldset>
    <legend><?= h(t('rep_title')) ?></legend>
    <?php if ($report): ?>
      <table><tr><th><?= h(t('rep_rule')) ?></th><th class="n"><?= h(t('rep_count')) ?></th></tr>
      <?php arsort($report); foreach ($report as $k => $v): ?>
        <tr><td><?= h(t('r_' . $k)) ?></td><td class="n"><?= (int)$v ?></td></tr>
      <?php endforeach; ?></table>
    <?php else: ?><p class="mut"><?= h(t('rep_clean')) ?></p><?php endif; ?>
  </fieldset>

  <fieldset>
    <legend><?= h(t('audit_title')) ?></legend>
    <?php if ($rest): ?>
      <table><tr><th><?= h(t('audit_char')) ?></th><th><?= h(t('audit_code')) ?></th>
        <th><?= h(t('audit_name')) ?></th><th class="n"><?= h(t('rep_count')) ?></th></tr>
      <?php foreach ($rest as $r): ?>
        <tr><td><code><?= h($r['char']) ?></code></td>
            <td><code>U+<?= strtoupper(str_pad(dechex($r['cp']), 4, '0', STR_PAD_LEFT)) ?></code></td>
            <td class="mut"><?= h($r['name']) ?></td>
            <td class="n"><?= (int)$r['count'] ?></td></tr>
      <?php endforeach; ?></table>
    <?php else: ?><p class="mut"><?= h(t('audit_clean')) ?></p><?php endif; ?>
  </fieldset>
</div>
<?php endif; ?>

<footer>
  <p><?= h(t('note')) ?></p>
  <p>CLI: <code>php llm-sanitizer.php --profile=<?= h($profile) ?> &lt; in.txt &gt; out.txt</code>
     &middot; <code>--report</code> &middot; <code>--no-tidy</code> &middot; <code>--help</code></p>
  <p>LLM Sanitizer v<?= h(LlmSanitizer::VERSION) ?>, MIT License, (c) 2026 Rolid spol. s r.o.</p>
  <p><a href=https://github.com/MrRolid/LLM-Sanitizer> Github </a></p>
</footer>
</div>
<script>
var PROFILE_DEFAULTS = <?= json_encode($profileDefaultsJson, JSON_UNESCAPED_UNICODE) ?>;
function applyProfile(p) {
  var d = PROFILE_DEFAULTS[p];
  if (!d) return;
  document.querySelectorAll('input[data-rule]').forEach(function (el) {
    if (Object.prototype.hasOwnProperty.call(d, el.dataset.rule)) { el.checked = !!d[el.dataset.rule]; }
  });
  document.querySelector('#langform input[name=profile]').value = p;
}
</script>
</body>
</html>
