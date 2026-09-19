import { describe, expect, it } from 'vitest'
import { readFileSync } from 'node:fs'
import { resolve } from 'node:path'

const source = readFileSync(resolve(process.cwd(), 'src/views/admin/ProxiesView.vue'), 'utf8')

describe('proxy capacity UI', () => {
  it('shows current usage against all three configured limits', () => {
    expect(source).toContain("{ key: 'current_rpm'")
    expect(source).toContain("row.max_concurrency || '∞'")
    expect(source).toContain("row.max_rpm || '∞'")
    expect(source).toContain("row.max_accounts || '∞'")
  })

  it('sends capacity limits on create and update', () => {
    for (const field of ['max_accounts', 'max_rpm', 'max_concurrency']) {
      expect(source).toContain(`createForm.${field}`)
      expect(source).toContain(`editForm.${field}`)
      expect(source).toContain(`${field}: createForm.${field}`)
      expect(source).toContain(`${field}: editForm.${field}`)
    }
  })
})
