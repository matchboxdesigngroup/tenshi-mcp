// Credential-line redaction, applied in this process to every piece of file
// or log content before a tool returns it. A line that looks like it carries
// a credential is replaced as a whole by REDACTED_LINE, so a partial line (cut
// at a byte cap or at the start of a log window) is redacted as reliably as a
// complete one. Tools apply it before filtering, selecting or cutting lines,
// so a filter or a byte cap cannot be used to probe the redacted text.
//
// The rules are deliberately broad: a false positive hides a harmless line, a
// false negative leaks a secret. They are heuristics and do not recognise
// every secret format; the path policy (src/policy/paths.js) keeps the files
// that hold credentials out of reach in the first place.
//
// Only the number of redacted lines leaves this module with the content; the
// redacted text is never logged or returned.

export const REDACTED_LINE = '[redacted credential line]'

// A credential-like name followed by an assignment: `DB_PASSWORD', '...'`,
// `"api_key": "..."`, `token=...`, `'secret' => ...`, `Authorization: ...`.
const ASSIGNMENT = new RegExp(
  '(?:pass(?:word|wd|phrase)?|pwd|secret|token|api[-_]?key|apikey|access[-_]?key|private[-_]?key|' +
  'client[-_]?secret|authorization|auth[-_](?:key|salt|token)|salt|credential|cookie|' +
  'sess(?:ion)?[-_]?id|db[-_]?user(?:name)?|[a-z0-9][-_]key)' +
  '[\\w.-]{0,40}?[\'"\\]]?\\s{0,8}(?:=>|[=:,])',
  'i'
)

const RULES = [
  ASSIGNMENT,
  // Credentials in a URL: scheme://user:password@host
  /[a-z][a-z0-9+.-]{0,20}:\/\/[^\s/@:]{1,256}:[^\s/@]{1,256}@/i,
  // HTTP authorization values
  /\b(?:bearer|basic)\s+[A-Za-z0-9._~+/-]{8,}/i,
  // AWS access key ids
  /\b(?:AKIA|ASIA)[A-Z0-9]{16}\b/,
  // JSON web tokens
  /\beyJ[A-Za-z0-9_-]{8,}\.eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}/,
  // Private key armour lines
  /-----(?:BEGIN|END) [A-Z0-9 ]*PRIVATE KEY(?: BLOCK)?-----/i,
  // A line that is only base64 with mixed case and digits, as in the body of
  // a key whose armour line is outside the text (a log window that starts
  // inside a key block)
  /^(?=[^A-Z]*[A-Z])(?=[^a-z]*[a-z])(?=[^0-9]*[0-9])\s*[A-Za-z0-9+/]{40,}={0,2}\s*$/
]

const BLOCK_BEGIN = /-----BEGIN [A-Z0-9 ]*PRIVATE KEY(?: BLOCK)?-----/i
const BLOCK_END = /-----END [A-Z0-9 ]*PRIVATE KEY(?: BLOCK)?-----/i

/**
 * Redact credential lines. Lines inside a private key block (from its BEGIN
 * line up to its END line, or to the end when the END line is missing) are
 * redacted as well.
 *
 * @param {readonly string[]} lines lines without their line terminators
 * @returns {{ lines: string[], redacted: boolean[], count: number }}
 */
export function redactLines(lines) {
  const out = []
  const redacted = []
  let inKeyBlock = false
  let count = 0
  for (const line of lines) {
    let hide = inKeyBlock
    if (!inKeyBlock && BLOCK_BEGIN.test(line)) {
      inKeyBlock = !BLOCK_END.test(line.slice(line.search(BLOCK_BEGIN) + 1))
      hide = true
    } else if (inKeyBlock && BLOCK_END.test(line)) {
      inKeyBlock = false
    }
    if (!hide) hide = RULES.some(rule => rule.test(line))
    out.push(hide ? REDACTED_LINE : line)
    redacted.push(hide)
    if (hide) count++
  }
  return { lines: out, redacted, count }
}

/**
 * Redact credential lines in a text, keeping its line terminators (`\n` and
 * `\r\n`) as they were.
 * @param {string} text
 * @returns {{ text: string, count: number }}
 */
export function redactText(text) {
  const raw = text.split('\n')
  const bodies = raw.map(l => (l.endsWith('\r') ? l.slice(0, -1) : l))
  const { lines, count } = redactLines(bodies)
  const joined = lines.map((l, i) => (raw[i].endsWith('\r') ? l + '\r' : l)).join('\n')
  return { text: joined, count }
}
