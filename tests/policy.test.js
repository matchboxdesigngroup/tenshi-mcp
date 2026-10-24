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
    ['backup.example.com.access.log'],
    ['shop.db.example.com.error.log'],
    ['wp-content/plugins/keyring/readme.txt'],
    ['wp-content/plugins/monkey/a.php'],
    ['wp-content/uploads/2026/10/café.txt'],
    ['wp-content/plugins/password-reset/readme.txt']
  ])('allows the ordinary path %j', p => {
    expect(isDenied(p)).toBe(false)
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

  it.each(credentialLines.map(l => [l]))('redacts %j', line => {
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

  it('redacts a credential line that was cut short', () => {
    expect(redactLines(["define( 'DB_PASSWORD', 'fa"]).count).toBe(1)
    expect(redactLines(['mysql://user:f']).count).toBe(0) // no value shown yet
  })

  it('keeps line terminators in redactText', () => {
    const text = 'a\r\nDB_PASSWORD=x\r\nb\nsecret: y\nc'
    expect(redactText(text)).toEqual({ text: `a\r\n${REDACTED_LINE}\r\nb\n${REDACTED_LINE}\nc`, count: 2 })
    expect(redactText('')).toEqual({ text: '', count: 0 })
    expect(redactText('x\n')).toEqual({ text: 'x\n', count: 0 })
  })

  it('stays fast on long hostile lines', () => {
    const started = Date.now()
    redactLines(['pass'.repeat(60000), 'a:'.repeat(100000), '://'.repeat(80000), 'aA1'.repeat(80000) + '!', '_key'.repeat(60000)])
    expect(Date.now() - started).toBeLessThan(2000)
  })
})
