import { describe, it, expect, vi, beforeEach } from 'vitest'

const SITE_CONFIG = {
  serverId: 'testserver',
  wordpressRoot: '/var/www/example.com/public',
  logDir: '/var/log/nginx'
}

describe('read_log path resolution', () => {
  beforeEach(() => {
    vi.resetModules()
  })

  it('resolves debug log to wordpressRoot/wp-content/debug.log', async () => {
    let capturedCmd = null
    vi.doMock('../src/ssh/executor.js', () => ({
      runCommand: async (serverId, cmd) => {
        capturedCmd = cmd
        return { stdout: 'log content', stderr: '', exitCode: 0 }
      }
    }))
    vi.doMock('../src/config/servers.js', () => ({
      resolveServerForSite: () => ({ serverId: 'testserver', site: SITE_CONFIG })
    }))
    const { readLogHandler } = await import('../src/tools/read-log.js')
    await readLogHandler({ site: 'example.com', log: 'debug', lines: 10 })
    expect(capturedCmd).toContain('/var/www/example.com/public/wp-content/debug.log')
    expect(capturedCmd).toMatch(/^tail -n 10/)
  })

  it('resolves error log to logDir/{site}.error.log', async () => {
    let capturedCmd = null
    vi.doMock('../src/ssh/executor.js', () => ({
      runCommand: async (serverId, cmd) => {
        capturedCmd = cmd
        return { stdout: '', stderr: '', exitCode: 0 }
      }
    }))
    vi.doMock('../src/config/servers.js', () => ({
      resolveServerForSite: () => ({ serverId: 'testserver', site: SITE_CONFIG })
    }))
    const { readLogHandler } = await import('../src/tools/read-log.js')
    await readLogHandler({ site: 'example.com', log: 'error', lines: 20 })
    expect(capturedCmd).toContain('/var/log/nginx/example.com.error.log')
  })

  it('resolves access log to logDir/{site}.access.log', async () => {
    let capturedCmd = null
    vi.doMock('../src/ssh/executor.js', () => ({
      runCommand: async (serverId, cmd) => {
        capturedCmd = cmd
        return { stdout: '', stderr: '', exitCode: 0 }
      }
    }))
    vi.doMock('../src/config/servers.js', () => ({
      resolveServerForSite: () => ({ serverId: 'testserver', site: SITE_CONFIG })
    }))
    const { readLogHandler } = await import('../src/tools/read-log.js')
    await readLogHandler({ site: 'example.com', log: 'access', lines: 30 })
    expect(capturedCmd).toContain('/var/log/nginx/example.com.access.log')
  })

  it('appends grep when filter is provided', async () => {
    let capturedCmd = null
    vi.doMock('../src/ssh/executor.js', () => ({
      runCommand: async (serverId, cmd) => {
        capturedCmd = cmd
        return { stdout: 'filtered', stderr: '', exitCode: 0 }
      }
    }))
    vi.doMock('../src/config/servers.js', () => ({
      resolveServerForSite: () => ({ serverId: 'testserver', site: SITE_CONFIG })
    }))
    const { readLogHandler } = await import('../src/tools/read-log.js')
    await readLogHandler({ site: 'example.com', log: 'error', lines: 10, filter: 'fatal' })
    expect(capturedCmd).toContain('grep -i "fatal"')
  })

  it('caps lines at 500', async () => {
    let capturedCmd = null
    vi.doMock('../src/ssh/executor.js', () => ({
      runCommand: async (serverId, cmd) => {
        capturedCmd = cmd
        return { stdout: '', stderr: '', exitCode: 0 }
      }
    }))
    vi.doMock('../src/config/servers.js', () => ({
      resolveServerForSite: () => ({ serverId: 'testserver', site: SITE_CONFIG })
    }))
    const { readLogHandler } = await import('../src/tools/read-log.js')
    await readLogHandler({ site: 'example.com', log: 'debug', lines: 9999 })
    expect(capturedCmd).toContain('tail -n 500')
  })

  it('returns structured output', async () => {
    vi.doMock('../src/ssh/executor.js', () => ({
      runCommand: async () => ({ stdout: 'line1\nline2', stderr: '', exitCode: 0 })
    }))
    vi.doMock('../src/config/servers.js', () => ({
      resolveServerForSite: () => ({ serverId: 'testserver', site: SITE_CONFIG })
    }))
    const { readLogHandler } = await import('../src/tools/read-log.js')
    const result = await readLogHandler({ site: 'example.com', log: 'debug', lines: 10 })
    expect(result.site).toBe('example.com')
    expect(result.log).toBe('debug')
    expect(result.content).toBe('line1\nline2')
    expect(result.resolvedPath).toBeTruthy()
    expect(result.retrievedAt).toMatch(/^\d{4}-\d{2}-\d{2}T/)
  })
})
