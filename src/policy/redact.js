// Credential-line redaction, applied in this process to every piece of file
// or log content before a tool returns it. A line that looks like it carries
// a credential is replaced as a whole by REDACTED_LINE. Tools classify every
// line on its full text before filtering, selecting or cutting anything, so
// neither a filter nor a byte cap chosen by the caller changes which lines
// are redacted (see src/tools/read-file.js and src/tools/read-log.js).
//
// The rules are deliberately broad: a false positive hides a harmless line, a
// false negative leaks a secret. They are heuristics and do not recognise
// every secret format; the path policy (src/policy/paths.js) keeps the files
// that hold credentials out of reach in the first place. Every rule is linear
// in the line length (bounded quantifiers, no nested repetition), so a
// hostile line cannot make redaction slow.
//
// Only the number of redacted lines leaves this module with the content; the
// redacted text is never logged or returned.

export const REDACTED_LINE = '[redacted credential line]'

const KEYWORDS =
  'pass(?:word|wd|phrase|code)?|pwd|secret|token|api[-_]?key|apikey|access[-_]?key|private[-_]?key|' +
  'client[-_]?secret|authorization|auth[-_]?(?:key|salt|token)|salt|credential|cookie|signature|nonce|' +
  'sess(?:ion)?[-_]?id|db[-_]?user(?:name)?|[a-z0-9][-_]key'

// A credential-like name followed by an assignment: `NAME', '...'`,
// `"name": "..."`, `name=...`, `$a['name'] = ...`, `["name"]=>`, `Name: ...`.
// Up to three closing quotes or brackets may sit between name and operator.
const ASSIGNMENT = new RegExp(`(?:${KEYWORDS})[\\w.-]{0,40}?['"\`\\])}]{0,3}\\s{0,8}(?:=>|:=|[=:,])`, 'i')

// What may follow an assignment whose value is on the next line(s): an
// opening quote or bracket, a YAML block indicator, a line continuation.
const VALUE_FOLLOWS = /^\s{0,64}(?:['"`(\[{]\s{0,8})?(?:[|>][-+0-9]{0,3}\s{0,8})?(?:\\\s{0,8})?$/
const BLOCK_SCALAR = /[|>][-+0-9]{0,3}\s{0,8}$/

const XML_ELEMENT = new RegExp(`<\\s{0,8}[\\w:.-]{0,40}?(?:${KEYWORDS})[\\w:.-]{0,40}(?:\\s[^<>]{0,512})?>`, 'i')
const CLI_PASSWORD_COMMAND = /\b(?:mysql\w{0,16}|mariadb\w{0,16}|sshpass)\b/i
const CLI_USER_COMMAND = /\b(?:curl|wget)\b/i

/** Rules that look at one line. Each is a function, so a rule may combine linear tests. */
const RULES = [
  line => ASSIGNMENT.test(line),
  // Credential-like query-string parameters: ?key=..., &sig=..., &code=...
  line => /[?&;][\w.-]{0,64}?(?:key|token|sig|signature|secret|pass|pwd|auth|nonce|code|hash|session|sid)[\w.-]{0,32}=[^&\s#]/i.test(line),
  // Any user information in a URL: scheme://user:password@, scheme://:password@, scheme://token@
  line => /[a-z][a-z0-9+.-]{0,20}:\/\/[^\s/@]{1,512}@/i.test(line),
  // HTTP authorization values
  line => /\b(?:bearer|basic|digest)\s{1,8}[A-Za-z0-9._~+/=-]{6,}/i.test(line),
  // Cloud access key ids
  line => /\b(?:AKIA|ASIA|AGPA|AIDA|AROA|ANPA)[A-Z0-9]{12,}/.test(line),
  // JSON web tokens (header and payload are enough)
  line => /\beyJ[A-Za-z0-9_-]{4,}\.[A-Za-z0-9_-]{4,}/.test(line),
  // Well-known token prefixes
  line => /\b(?:gh[pousr]_[A-Za-z0-9]{8,}|github_pat_\w{8,}|(?:sk|rk|pk)_(?:live|test)_[A-Za-z0-9]{8,}|whsec_[A-Za-z0-9]{8,}|xox[abprse]-[A-Za-z0-9-]{8,}|xapp-[A-Za-z0-9-]{8,}|AIza[0-9A-Za-z_-]{16,}|glpat-[A-Za-z0-9_-]{8,}|npm_[A-Za-z0-9]{16,}|ya29\.[A-Za-z0-9_-]{8,}|SG\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}|hf_[A-Za-z0-9]{16,}|shp(?:at|ss|ca|pa)_[A-Fa-f0-9]{16,})/.test(line),
  // Credential-like XML or HTML elements: <Password>, <api_key>, <db:secret ...>
  line => XML_ELEMENT.test(line),
  // Password options on a command line: --password value, mysql -pvalue, sshpass -p value
  line => /\s--?(?:password|passwd|pass|pwd)(?:\s{1,8}|=)\S/i.test(line),
  line => CLI_PASSWORD_COMMAND.test(line) && /\s-p[^\s-]|\bsshpass\s{1,8}-p\s{0,8}\S/i.test(line),
  line => /\bredis-cli\b/i.test(line) && /\s(?:-a|--pass)\s{1,8}\S/.test(line),
  line => CLI_USER_COMMAND.test(line) && /\s(?:-u|--user)\s{0,8}[^\s:]{1,256}:\S/.test(line),
  // Prose: "the password is ...", "passcode was ..."
  line => /\b(?:password|passphrase|passcode)\b[^\S\n]{1,8}(?:is|was|set to|reset to|changed to|=|:)[^\S\n]{1,8}\S/i.test(line),
  // Private key armour lines
  line => /-----(?:BEGIN|END) [A-Z0-9 ]{0,40}PRIVATE KEY(?: BLOCK)?-----/i.test(line),
  // A line that is only base64 with mixed case and digits, as in a key body
  line => /^(?=[^A-Z]*[A-Z])(?=[^a-z]*[a-z])(?=[^0-9]*[0-9])\s*[A-Za-z0-9+/]{40,}={0,2}\s*$/.test(line)
]

const BLOCK_BEGIN = /-----BEGIN [A-Z0-9 ]{0,40}PRIVATE KEY(?: BLOCK)?-----/i
const BLOCK_END = /-----END [A-Z0-9 ]{0,40}PRIVATE KEY(?: BLOCK)?-----/i

function indentOf(line) {
  const m = /^[ \t]*/.exec(line)
  return m[0].length
}

/**
 * Redact credential lines. Beyond the single-line rules:
 *   - lines inside a private key block (from its BEGIN line to its END line,
 *     or to the end when the END line is missing) are redacted;
 *   - an END line with no BEGIN before it in the text (a log window that
 *     starts inside a key block) redacts every line above it as well;
 *   - an assignment whose value is not on its own line redacts the value:
 *     the next non-blank line, or, for a YAML block scalar (`|` or `>`),
 *     every following line indented deeper than the key.
 *
 * @param {readonly string[]} lines lines without their line terminators
 * @returns {{ lines: string[], redacted: boolean[], count: number }}
 */
export function redactLines(lines) {
  const redacted = new Array(lines.length).fill(false)
  let inKeyBlock = false
  let sawBegin = false
  /** @type {null | { block: boolean, indent: number }} */
  let continuation = null

  for (let i = 0; i < lines.length; i++) {
    const line = lines[i]
    let hide = false

    if (continuation) {
      if (continuation.block) {
        if (line.trim() === '' || indentOf(line) > continuation.indent) hide = true
        else continuation = null
      } else if (line.trim() !== '') {
        hide = true
        continuation = null
      }
    }

    if (inKeyBlock) {
      hide = true
      if (BLOCK_END.test(line)) inKeyBlock = false
    } else if (BLOCK_BEGIN.test(line)) {
      hide = true
      sawBegin = true
      inKeyBlock = !BLOCK_END.test(line.slice(line.search(BLOCK_BEGIN) + 1))
    } else if (BLOCK_END.test(line)) {
      hide = true
      if (!sawBegin) for (let j = 0; j < i; j++) redacted[j] = true
    }

    if (!hide && RULES.some(rule => rule(line))) hide = true

    const assignment = ASSIGNMENT.exec(line)
    if (assignment) {
      const rest = line.slice(assignment.index + assignment[0].length)
      if (VALUE_FOLLOWS.test(rest)) continuation = { block: BLOCK_SCALAR.test(rest), indent: indentOf(line) }
    }

    redacted[i] = redacted[i] || hide
  }

  const out = lines.map((line, i) => (redacted[i] ? REDACTED_LINE : line))
  return { lines: out, redacted, count: redacted.filter(Boolean).length }
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
