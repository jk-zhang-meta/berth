import { describe, expect, it } from 'vitest'
import { readFileSync } from 'node:fs'
import { resolve } from 'node:path'

const source = readFileSync(resolve(process.cwd(), 'src/views/admin/ProxiesView.vue'), 'utf8')

describe('proxy exit profile UI', () => {
  it('shows verified exit IP and timezone separately from the proxy endpoint', () => {
    expect(source).toContain("t('admin.proxies.exitIP')")
    expect(source).toContain('row.ip_address')
    expect(source).toContain('row.timezone')
    expect(source).toContain('row.exit_verified')
    expect(source).toContain('formatUTCOffset(row.utc_offset_seconds)')
    expect(source).toContain("t('admin.proxies.exitCheckedAt')")
    expect(source).toContain('formatExitCheckedAt(row.exit_checked_at)')
  })

  it('keeps the last verified exit profile when a transient connectivity retest fails', () => {
    const start = source.indexOf("target.latency_status = 'failed'")
    const end = source.indexOf('target.latency_message = result.message', start)
    expect(start).toBeGreaterThanOrEqual(0)
    expect(end).toBeGreaterThan(start)
    const failureBranch = source.slice(start, end)
    expect(failureBranch).not.toContain('target.ip_address = undefined')
    expect(failureBranch).not.toContain('target.timezone = undefined')
  })
})
