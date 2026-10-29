import { describe, it, expect } from 'vitest'
import {
  isDenied,
  isAllowed,
  extensionOf,
  isValidAllowedDirectory,
  isValidAllowedExtension
} from '../src/policy/paths.js'
import { redactLines, redactText, REDACTED_LINE } from '../src/policy/redact.js'

// Unit tests of the sensitive-file policy and of credential redaction. The
// same rules are exercised through the tools against the in-process SFTP
// fake in tests/confinement-policy.test.js.

describe('isDenied: built-in denylist', () => {
  const denied = {
    'WordPress configuration and its variants': [
      'wp-config.php', 'WP-CONFIG.PHP', 'Wp-Config.php', 'wp-config.php.bak', 'wp-config.php~',
      'wp-config.php.save', 'wp-config.php.swp', 'wp-config-sample.php', 'wp-config.old', 'wp-config.txt',
      'wp_config.php', 'wpconfig.php', 'wp-config.php.', 'wp-config.php ', 'wp-config.php. . ',
      'sub/dir/wp-config.php', '#wp-config.php#', 'ｗｐ-config.php', 'wp-content/wp-config.php/x.txt'
    ],
    'environment files': [
      '.env', '.ENV', '.env.local', '.env.production', '.env.bak', '.envrc', 'production.env', 'config/app.ENV',
      '．env'
    ],
    'database files and dumps': [
      'dump.sql', 'DUMP.SQL', 'db.sql.gz', 'export.sql.txt', 'site.sqlite', 'site.sqlite3', 'data.db', 'x.dump',
      'wp-content/x.SqL', 'dump.sql.', 'dump.txt', 'dumps/a.txt'
    ],
    'backups and archives': [
      'backup.zip', 'site-backup.tar.gz', 'a.tgz', 'a.7z', 'a.rar', 'a.bak', 'a.BAK', 'a.old', 'a.orig', 'index.php.bak',
      'index.php~', 'wp-content/backups/x.txt', 'wp-content/ai1wm-backups/site.wpress', 'wp-content/backups-dup-lite/a.php',
      'wp-content/updraft/log.txt', 'wp-content/BackUps/x.txt', 'backup.txt', 'x.wpress', 'site.jpa', 'db.sql.bz2'
    ],
    'keys and certificates': [
      'id_rsa', 'id_rsa.pub', 'ID_ED25519', 'id_ecdsa', 'server.key', 'server.KEY', 'server.pem', 'cert.p12',
      'keystore.jks', 'x.ppk', 'x.pfx', 'site.crt', 'private.asc'
    ],
    'hidden files and directories': [
      '.htaccess', '.htpasswd', '.git/config', '.ssh/authorized_keys', '.aws/credentials', 'wp-content/.hidden/x.php',
      '.user.ini', '.npmrc', '.DS_Store'
    ],
    'credential files': [
      'auth.json', 'credentials.json', 'secrets.yml', 'secret.php', 'passwords.txt', 'htpasswd', 'authorized_keys',
      'known_hosts', 'shadow', 'secrets.prod.yml', 'credentials.local.json'
    ],
    'extensions anywhere in the name': [
      'dump.sql.1.txt', 'site.sql.20261024.txt', 'db-export.sql.txt.php', 'mysite.sql.gz.part.txt', 'index.php.bak.1.txt',
      'server.key.2026.txt', 'private.pem.txt.php'
    ],
    'denied names with any number of parts': [
      'secrets.prod.local.yml', 'credentials.1.2.json', 'id_rsa.old.1.txt', 'backup.2026.10.php'
    ],
    'denied words in file names': [
      'site-backup.php', 'mysitebackup.txt', 'db-dump.txt', 'site_dump_1.txt', 'x.bak-1.txt', 'my-credentials.php', 'app-secrets.php'
    ],
    'denied directory names': [
      'wp-content/uploads/db-dumps/a.txt', 'wp-content/uploads/bak/a.txt', 'wp-content/uploads/old/a.txt',
      'wp-content/sql/a.txt', 'wp-content/site-orig/a.txt', 'wp-content/databases/a.txt'
    ],
    'environment configuration files': [
      'local-config.php', 'production-config.php', 'staging-config.php', 'db-config.php', 'wp.config.php',
      'config-local.php', 'settings.local.php', 'dev_settings.php'
    ],
    'names that only match once trailing dots and spaces are removed': [
      'export.sql ', 'site.key. .', 'id_rsa ', 'archive.zip.', 'x.env . '
    ],
    'unsafe characters and malformed paths': [
      'a\u0000b.php', 'a\nb.php', 'a‮b.php', 'a​b.php', 'a b.php', '\ud800.php', '', '/abs.php',
      'a//b.php', './a.php', 'a/../b.php', 'a/', undefined, null, 42
    ]
  }

  for (const [category, paths] of Object.entries(denied)) {
    it.each(paths.map(p => [p]))(`refuses ${category}: %j`, p => {
      expect(isDenied(p)).toBe(true)
    })
  }

  it.each([
    ['index.php'],
    ['wp-content/debug.log'],
    ['wp-content/plugins/example/readme.txt'],
    ['wp-content/plugins/akismet/class.akismet.php'],
    ['wp-content/themes/example/style.css'],
    ['wp-includes/js/jquery/jquery.min.js'],
    ['example.com.error.log'],
    ['wp-content/plugins/example-shop/templates/form-lost-password.php'],
    ['wp-content/themes/example/old-style-notes.txt'],
    ['wp-content/plugins/example/includes/class-config.php'],
    ['wp-content/plugins/example/readme.1.txt'],
    ['wp-content/plugins/keyring/readme.txt'],
    ['wp-content/plugins/monkey/a.php'],
    ['wp-content/uploads/2026/10/café.txt'],
    ['wp-content/plugins/password-reset/readme.txt']
  ])('allows the ordinary path %j', p => {
    expect(isDenied(p)).toBe(false)
  })
})

describe('isDenied: registry prefix of log file names', () => {
  it.each([
    ['backup.example.com', 'backup.example.com.access.log'],
    ['shop.db.example.com', 'shop.db.example.com.error.log'],
    ['secrets.example.net', 'secrets.example.net.access.log'],
    ['my-dump.example.org', 'my-dump.example.org.error.log']
  ])('skips the site name %s at the start of %s', (site, name) => {
    expect(isDenied(name)).toBe(true)
    expect(isDenied(name, { trustedPrefix: site })).toBe(false)
  })

  it('still applies every rule to the rest of the name and to directories', () => {
    const site = 'backup.example.com'
    for (const p of [`${site}.sql`, `${site}.error.log.bak`, `${site}.error.sql.log`, `${site}..env`, `old/${site}.error.log`, '.env', 'wp-config.php']) {
      expect(isDenied(p, { trustedPrefix: site })).toBe(true)
    }
    // Only a prefix followed by a dot is skipped, and only in the file name.
    expect(isDenied('backup.example.comX.error.log', { trustedPrefix: site })).toBe(true)
    expect(isDenied(`${site}/x.txt`, { trustedPrefix: site })).toBe(true)
  })
})

describe('isAllowed: per-site allowlist', () => {
  const allow = { extensions: ['.php', '.txt'], directories: ['wp-content/plugins', 'wp-content/themes/example'] }

  it.each([
    ['wp-content/plugins/x.php', true],
    ['wp-content/plugins/demo/readme.txt', true],
    ['wp-content/plugins/demo/README.TXT', true],
    ['wp-content/themes/example/functions.php', true],
    ['wp-content/themes/example/sub/a.php', true],
    // directory not listed
    ['index.php', false],
    ['wp-content/x.php', false],
    ['wp-content/themes/other/functions.php', false],
    ['wp-content/themes/example2/functions.php', false],
    // whole segments, case-sensitive
    ['wp-content/plugins-extra/x.php', false],
    ['wp-content/Plugins/x.php', false],
    // extension not listed, or none
    ['wp-content/plugins/demo/data.csv', false],
    ['wp-content/plugins/demo/README', false],
    ['wp-content/plugins/demo/.php', false],
    ['wp-content/plugins/demo/x.', false],
    ['wp-content/plugins/demo/x.php.txt2', false],
    // a listed directory itself is not a file
    ['wp-content/plugins', false],
    // malformed
    ['wp-content/plugins/../x.php', false],
    ['/wp-content/plugins/x.php', false],
    ['', false]
  ])('%j -> %s', (p, expected) => {
    expect(isAllowed(allow, p)).toBe(expected)
  })

  it('"." allows the whole tree, extensions still apply', () => {
    const root = { extensions: ['.php'], directories: ['.'] }
    expect(isAllowed(root, 'index.php')).toBe(true)
    expect(isAllowed(root, 'a/b/c.php')).toBe(true)
    expect(isAllowed(root, 'a/b/c.txt')).toBe(false)
  })

  it('refuses everything without a usable allowlist', () => {
    for (const bad of [undefined, null, {}, { extensions: ['.php'] }, { directories: ['.'] }, { extensions: '.php', directories: ['.'] }]) {
      expect(isAllowed(bad, 'index.php')).toBe(false)
    }
  })

  it('extensionOf takes the final extension, lower-cased', () => {
    expect(extensionOf('a.PHP')).toBe('.php')
    expect(extensionOf('a.tar.gz')).toBe('.gz')
    expect(extensionOf('.htaccess')).toBe('')
    expect(extensionOf('README')).toBe('')
    expect(extensionOf('x.')).toBe('')
  })

  it('validates configured entries', () => {
    expect(isValidAllowedExtension('.php')).toBe(true)
    expect(isValidAllowedExtension('php')).toBe(false)
    expect(isValidAllowedExtension('.sql')).toBe(false)
    expect(isValidAllowedExtension('.tar.gz')).toBe(false)
    expect(isValidAllowedDirectory('.')).toBe(true)
    expect(isValidAllowedDirectory('wp-content/plugins')).toBe(true)
    expect(isValidAllowedDirectory('wp-content/../x')).toBe(false)
    expect(isValidAllowedDirectory('.git')).toBe(false)
    expect(isValidAllowedDirectory('wp-content/updraft')).toBe(false)
  })
})

describe('credential redaction', () => {
  // Fake values only.
  const credentialLines = [
    "define( 'DB_PASSWORD', 'fake-db-pass' );",
    "define('DB_USER', 'fake_user');",
    "define( 'AUTH_KEY',         'fake-auth-key-value' );",
    "define( 'SECURE_AUTH_SALT', 'fake-salt' );",
    "define( 'NONCE_KEY', 'fake-nonce' );",
    'DB_PASSWORD=fake-db-pass',
    'export STRIPE_SECRET_KEY=sk_fake_000',
    '"api_key": "fake-api-key"',
    "'password' => 'fake-pass',",
    'password: fake-pass',
    'client_secret = fake',
    'GET /wp-login.php?action=rp&token=fake-token HTTP/1.1',
    'Authorization: Bearer fake.bearer.token',
    'Cookie: wordpress_logged_in_x=fake',
    'PHPSESSID=fakesession',
    'connecting to mysql://user:fake-pass@db.example.com:3306/wp',
    'curl -H "x" https://user:fake@example.com/',
    'Basic ZmFrZTpmYWtlZmFrZQ==',
    'key id AKIAABCDEFGHIJKLMNOP in config',
    'jwt eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJmYWtlIn0.c2lnbmF0dXJlZmFrZQ',
    '-----BEGIN OPENSSH PRIVATE KEY-----',
    'MIIEowIBAAKCAQEAfakefakefakefakeFAKEFAKE0123456789abcdefABCDEF'
  ]

  // Synthetic values only; token-like values are assembled at run time.
  const join = (...p) => p.join('')
  const moreCredentialLines = [
    "$creds['password'] = 'FAKEVALUE';",
    '$config["api_key"] = "FAKEVALUE";',
    'GET /wp-login.php?action=rp&key=FAKEVALUE&login=example HTTP/1.1',
    'GET /wp-activate.php?key=FAKEVALUE HTTP/1.1',
    'GET /checkout/order-received/12/?key=FAKEVALUE HTTP/1.1',
    'GET /file?sv=1&se=2&sig=FAKEVALUE HTTP/1.1',
    'GET /callback?code=FAKEVALUE&state=1 HTTP/1.1',
    'connect redis://:FAKEVALUE@cache.example.com:6379',
    join('clone https://', 'FAKEVALUE0000', '@git.example.com/x.git'),
    '<Password>FAKEVALUE</Password>',
    '<db:secret type="x">FAKEVALUE</db:secret>',
    'mysqldump -uexample -pFAKEVALUE example_db',
    'mysql --user=example --password FAKEVALUE',
    'sshpass -p FAKEVALUE ssh example',
    'redis-cli -h cache.example.com -a FAKEVALUE ping',
    'curl -u example:FAKEVALUE https://example.com/',
    'the new password is FAKEVALUE',
    'Passcode was FAKEVALUE',
    join('token ', 'gh', 'p_', 'FAKEVALUE0000'),
    join('key ', 'sk', '_live_', 'FAKEVALUE0000'),
    join('key ', 'xox', 'b-', 'FAKEVALUE-0000'),
    join('key ', 'AI', 'za', 'FAKEVALUE0000FAKE'),
    join('jwt ', 'eyJ', 'FAKE', '.', 'FAKEVALUE')
  ]

  it.each(moreCredentialLines.map((l, i) => [i, l]))('redacts credential line form %i', (_, line) => {
    expect(redactLines([line])).toEqual({ lines: [REDACTED_LINE], redacted: [true], count: 1 })
  })

  it.each([
    ['a PHP define split over two lines', ["define( 'DB_PASSWORD',", "  'FAKEVALUE' );", 'next'], [true, true, false]],
    ['a var_dump key and its value line', ['  ["password"]=>', '  string(9) "FAKEVALUE"', '  ["user"]=>'], [true, true, false]],
    ['a JSON key and its value line', ['  "secret":', '    "FAKEVALUE",', '  "name": "x"'], [true, true, false]],
    ['a YAML block scalar', ['secret: |', '  FAKEVALUE1', '', '  FAKEVALUE2', 'other: x'], [true, true, true, true, false]],
    ['a folded YAML block scalar', ['  token: >-', '    FAKEVALUE', '  other: x'], [true, true, false]]
  ])('redacts the value of %s', (_, lines, expected) => {
    expect(redactLines(lines).redacted).toEqual(expected)
  })

  it('redacts every line above an END armour line when the text starts inside a key block', () => {
    const window = ['AbC0FAKEbodyLine', 'Zz9=', '-----END PRIVATE KEY-----', 'after']
    expect(redactLines(window).redacted).toEqual([true, true, true, false])
  })

  it.each(credentialLines.map((l, i) => [i, l]))('redacts basic credential line form %i', (_, line) => {
    const { lines, count } = redactLines([line])
    expect(lines).toEqual([REDACTED_LINE])
    expect(count).toBe(1)
  })

  it.each([
    ['PHP Fatal error: Uncaught Error: Call to undefined function wp_check_password() in /x.php:12'],
    ['PHP Notice: Undefined index: token in plugin.php on line 3'],
    ['GET /wp-content/themes/example/style.css HTTP/1.1 200'],
    ['<?php echo 1;'],
    ['b'.repeat(100)],
    ['L'.repeat(5000)],
    ['the passage of time'],
    ['']
  ])('keeps the ordinary line %j', line => {
    expect(redactLines([line])).toEqual({ lines: [line], redacted: [false], count: 0 })
  })

  it('redacts a whole private key block, also without an END line', () => {
    const block = ['before', '-----BEGIN RSA PRIVATE KEY-----', 'short', 'abc def', '-----END RSA PRIVATE KEY-----', 'after']
    expect(redactLines(block).lines).toEqual(['before', REDACTED_LINE, REDACTED_LINE, REDACTED_LINE, REDACTED_LINE, 'after'])
    const cut = ['x', '-----BEGIN PRIVATE KEY-----', 'abc', 'def']
    expect(redactLines(cut)).toEqual({ lines: ['x', REDACTED_LINE, REDACTED_LINE, REDACTED_LINE], redacted: [false, true, true, true], count: 3 })
  })

  it('classifies whole lines: a line cut before the end of its secret is not reliably recognised', () => {
    // redactLines sees complete lines only. Callers never hand it a line cut
    // at a caller-chosen offset: read_file classifies the line at the cut on
    // its text beyond the cut (tests/redaction-cut.test.js), read_log drops
    // a partial first line after classification.
    expect(redactLines(["define( 'DB_PASSWORD', 'fa"]).count).toBe(1)
    expect(redactLines(['scheme://user:p']).count).toBe(0)
    expect(redactLines(['scheme://user:p@host']).count).toBe(1)
  })

  it('keeps line terminators in redactText', () => {
    const text = 'a\r\nDB_PASSWORD=x\r\nb\nsecret: y\nc'
    expect(redactText(text)).toEqual({ text: `a\r\n${REDACTED_LINE}\r\nb\n${REDACTED_LINE}\nc`, count: 2 })
    expect(redactText('')).toEqual({ text: '', count: 0 })
    expect(redactText('x\n')).toEqual({ text: 'x\n', count: 0 })
  })

  it.each([
    ['repeated keywords', 'password'],
    ['repeated keyword and separator', 'token= '],
    ['repeated query parameters', '&key'],
    ['repeated scheme separators', 'a://'],
    ['repeated user information', 'a://x:'],
    ['repeated element openings', '<pass'],
    ['repeated element with attributes', '<secret a'],
    ['repeated command flags', 'mysql -'],
    ['repeated authorization schemes', 'Bearer '],
    ['repeated token prefixes', 'eyJa.'],
    ['repeated closing quotes', "pass'])"],
    ['mixed base64 classes', 'aA1'],
    ['whitespace', ' \t'],
    ['colons', ':'],
    ['dashes', '-----BEGIN '],
    ['key suffixes', '_key']
  ])('stays linear on a 1 MB line of %s', (_, unit) => {
    const line = unit.repeat(Math.ceil(1024 * 1024 / unit.length)) + '!'
    const started = Date.now()
    redactLines([line, line.slice(1)])
    expect(Date.now() - started).toBeLessThan(1500)
  })
})
