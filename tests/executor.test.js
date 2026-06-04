import { describe, it, expect, vi, beforeEach } from 'vitest'

describe('runCommand allowlist', () => {
  beforeEach(() => {
    vi.resetModules()
  })

  it('allows tail', async () => {
    vi.doMock('../src/ssh/client.js', () => ({
      getConnection: async () => ({
        execCommand: async (cmd) => ({ stdout: 'line1\nline2', stderr: '', code: 0 })
      })
    }))
    const { runCommand } = await import('../src/ssh/executor.js')
    const result = await runCommand('anyserver', 'tail -n 10 /var/log/app.log')
    expect(result.stdout).toBe('line1\nline2')
    expect(result.exitCode).toBe(0)
  })

  it('allows head', async () => {
    vi.doMock('../src/ssh/client.js', () => ({
      getConnection: async () => ({
        execCommand: async () => ({ stdout: 'data', stderr: '', code: 0 })
      })
    }))
    const { runCommand } = await import('../src/ssh/executor.js')
    const result = await runCommand('anyserver', 'head -c 1000 /var/www/file.php')
    expect(result.exitCode).toBe(0)
  })

  it('rejects rm', async () => {
    vi.doMock('../src/ssh/client.js', () => ({
      getConnection: async () => ({ execCommand: async () => ({}) })
    }))
    const { runCommand } = await import('../src/ssh/executor.js')
    await expect(runCommand('anyserver', 'rm -rf /var/www')).rejects.toThrow(
      'Command not allowed: rm'
    )
  })

  it('rejects bash', async () => {
    vi.doMock('../src/ssh/client.js', () => ({
      getConnection: async () => ({ execCommand: async () => ({}) })
    }))
    const { runCommand } = await import('../src/ssh/executor.js')
    await expect(runCommand('anyserver', 'bash -c "cat /etc/passwd"')).rejects.toThrow(
      'Command not allowed: bash'
    )
  })

  it('rejects empty command', async () => {
    vi.doMock('../src/ssh/client.js', () => ({
      getConnection: async () => ({ execCommand: async () => ({}) })
    }))
    const { runCommand } = await import('../src/ssh/executor.js')
    await expect(runCommand('anyserver', '')).rejects.toThrow('Command not allowed')
  })

  it('returns stderr without throwing on non-zero exit', async () => {
    vi.doMock('../src/ssh/client.js', () => ({
      getConnection: async () => ({
        execCommand: async () => ({ stdout: '', stderr: 'No such file', code: 1 })
      })
    }))
    const { runCommand } = await import('../src/ssh/executor.js')
    const result = await runCommand('anyserver', 'tail -n 10 /nonexistent')
    expect(result.exitCode).toBe(1)
    expect(result.stderr).toBe('No such file')
  })
})
