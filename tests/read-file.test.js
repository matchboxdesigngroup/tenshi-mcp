import { describe, it, expect, vi, beforeEach } from 'vitest'

const SITE_CONFIG = {
  serverId: 'testserver',
  wordpressRoot: '/var/www/example.com/public',
  logDir: '/var/log/nginx'
}

describe('read_file path confinement', () => {
  beforeEach(() => {
    vi.resetModules()
  })

  it('resolves valid relative path correctly', async () => {
    let capturedCmd = null
    vi.doMock('../src/ssh/executor.js', () => ({
      runCommand: async (serverId, cmd) => {
        capturedCmd = cmd
        return { stdout: '<?php', stderr: '', exitCode: 0 }
      }
    }))
    vi.doMock('../src/config/servers.js', () => ({
      resolveServerForSite: () => ({ serverId: 'testserver', site: SITE_CONFIG })
    }))
    const { readFileHandler } = await import('../src/tools/read-file.js')
    await readFileHandler({ site: 'example.com', path: 'wp-config.php', maxBytes: 1000 })
    expect(capturedCmd).toContain('/var/www/example.com/public/wp-config.php')
    expect(capturedCmd).toMatch(/^head -c 1000/)
  })

  it('rejects path traversal attempt', async () => {
    vi.doMock('../src/ssh/executor.js', () => ({
      runCommand: async () => ({ stdout: '', stderr: '', exitCode: 0 })
    }))
    vi.doMock('../src/config/servers.js', () => ({
      resolveServerForSite: () => ({ serverId: 'testserver', site: SITE_CONFIG })
    }))
    const { readFileHandler } = await import('../src/tools/read-file.js')
    await expect(
      readFileHandler({ site: 'example.com', path: '../../etc/passwd', maxBytes: 1000 })
    ).rejects.toThrow('Path escapes WordPress root')
  })

  it('rejects absolute path input', async () => {
    vi.doMock('../src/ssh/executor.js', () => ({
      runCommand: async () => ({ stdout: '', stderr: '', exitCode: 0 })
    }))
    vi.doMock('../src/config/servers.js', () => ({
      resolveServerForSite: () => ({ serverId: 'testserver', site: SITE_CONFIG })
    }))
    const { readFileHandler } = await import('../src/tools/read-file.js')
    await expect(
      readFileHandler({ site: 'example.com', path: '/etc/passwd', maxBytes: 1000 })
    ).rejects.toThrow('Path escapes WordPress root')
  })

  it('caps maxBytes at 51200', async () => {
    let capturedCmd = null
    vi.doMock('../src/ssh/executor.js', () => ({
      runCommand: async (serverId, cmd) => {
        capturedCmd = cmd
        return { stdout: 'data', stderr: '', exitCode: 0 }
      }
    }))
    vi.doMock('../src/config/servers.js', () => ({
      resolveServerForSite: () => ({ serverId: 'testserver', site: SITE_CONFIG })
    }))
    const { readFileHandler } = await import('../src/tools/read-file.js')
    await readFileHandler({ site: 'example.com', path: 'wp-config.php', maxBytes: 999999 })
    expect(capturedCmd).toContain('head -c 51200')
  })

  it('returns structured output with truncated flag', async () => {
    vi.doMock('../src/ssh/executor.js', () => ({
      runCommand: async () => ({ stdout: 'x'.repeat(100), stderr: '', exitCode: 0 })
    }))
    vi.doMock('../src/config/servers.js', () => ({
      resolveServerForSite: () => ({ serverId: 'testserver', site: SITE_CONFIG })
    }))
    const { readFileHandler } = await import('../src/tools/read-file.js')
    const result = await readFileHandler({ site: 'example.com', path: 'wp-config.php', maxBytes: 100 })
    expect(result.site).toBe('example.com')
    expect(result.requestedPath).toBe('wp-config.php')
    expect(result.resolvedPath).toBe('/var/www/example.com/public/wp-config.php')
    expect(result.content).toBe('x'.repeat(100))
    expect(result.truncated).toBe(true)
    expect(result.retrievedAt).toMatch(/^\d{4}-\d{2}-\d{2}T/)
  })
})
