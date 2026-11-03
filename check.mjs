// Monitor checker — függőség nélkül (Node 20). 10 percenként futtatja a GitHub Actions.
// Kimenet: R2 `monitor` bucket (monitor.json, daily/YYYY-MM.json) + `monitor-public` (szűrt másolat) + healthchecks ping.
// Titkok csak env-ből; a log csak elemnevet és állapotkódot ír, URL-t/hibaszöveget nem.
import crypto from 'node:crypto'
import fs from 'node:fs'

const TZ = 'Europe/Budapest'
const DRY = process.env.DRY === '1'                 // helyi próba: nincs R2-írás, nincs ping
const cfg = JSON.parse(fs.readFileSync(new URL('./services.json', import.meta.url), 'utf8'))
const SLOT_MIN = cfg.thresholds.slotMin
const RAW_KEEP_MS = 48 * 36e5
const sleep = (ms) => new Promise((r) => setTimeout(r, ms))
const localDay = (ts) => new Date(ts).toLocaleDateString('sv-SE', { timeZone: TZ })

// ─── R2 (SigV4) ─────────────────────────────────────────────────────────────────
const sha = (d) => crypto.createHash('sha256').update(d).digest('hex')
const hmac = (k, d) => crypto.createHmac('sha256', k).update(d).digest()
const enc = (s) => encodeURIComponent(s).replace(/[!'()*]/g, (c) => '%' + c.charCodeAt(0).toString(16).toUpperCase())
const { R2_ACCOUNT_ID: ACCT, R2_ACCESS_KEY_ID: KEY, R2_SECRET_ACCESS_KEY: SECRET } = process.env

async function r2(method, bucket, objKey, body) {
  const host = `${ACCT}.r2.cloudflarestorage.com`
  const path = '/' + bucket + '/' + objKey.split('/').map(enc).join('/')
  const payload = body == null ? '' : body
  const payloadHash = sha(payload)
  const amzDate = new Date().toISOString().replace(/[:-]|\.\d{3}/g, '')
  const date = amzDate.slice(0, 8)
  const h = { host, 'x-amz-content-sha256': payloadHash, 'x-amz-date': amzDate }
  if (body != null) h['content-type'] = 'application/json'
  const names = Object.keys(h).sort()
  const canonical = [method, path, '', names.map((n) => `${n}:${h[n]}\n`).join(''), names.join(';'), payloadHash].join('\n')
  const scope = `${date}/auto/s3/aws4_request`
  const sts = ['AWS4-HMAC-SHA256', amzDate, scope, sha(canonical)].join('\n')
  const sigKey = hmac(hmac(hmac(hmac('AWS4' + SECRET, date), 'auto'), 's3'), 'aws4_request')
  const signature = crypto.createHmac('sha256', sigKey).update(sts).digest('hex')
  return fetch(`https://${host}${path}`, {
    method, body: body == null ? undefined : payload,
    headers: { ...h, authorization: `AWS4-HMAC-SHA256 Credential=${KEY}/${scope}, SignedHeaders=${names.join(';')}, Signature=${signature}` },
    signal: AbortSignal.timeout(20000),
  })
}
async function r2Json(bucket, key) {
  const r = await r2('GET', bucket, key)
  if (r.status === 404) return null
  if (!r.ok) throw new Error(`R2 GET ${key}: ${r.status}`)
  return JSON.parse(await r.text())
}
async function r2Put(bucket, key, obj) {
  if (DRY) return
  const r = await r2('PUT', bucket, key, JSON.stringify(obj))
  if (!r.ok) throw new Error(`R2 PUT ${key}: ${r.status}`)
}

// ─── mérések ────────────────────────────────────────────────────────────────────
let hcChecks = null   // slug → check (egyszer töltjük le)
async function loadHc() {
  if (hcChecks) return hcChecks
  const r = await fetch('https://healthchecks.io/api/v3/checks/', { headers: { 'X-Api-Key': process.env.HC_API_KEY || '' }, signal: AbortSignal.timeout(15000) })
  if (!r.ok) throw new Error(`healthchecks API: ${r.status}`)
  hcChecks = Object.fromEntries((await r.json()).checks.map((c) => [c.slug, c]))
  return hcChecks
}

async function probeOnce(it) {
  const t0 = Date.now()
  if (it.kind === 'http') {
    const base = it.urlEnv ? process.env[it.urlEnv] : it.url
    if (!base) return { ok: false, code: 0, ms: 0 }
    const r = await fetch(base + (it.urlSuffix || ''), { redirect: 'manual', signal: AbortSignal.timeout(15000), headers: { 'user-agent': 'monitor-checker' } })
    return { ok: (it.expect || [200]).includes(r.status), code: r.status, ms: Date.now() - t0 }
  }
  if (it.kind === 'statuspage') {
    const r = await fetch(it.url, { signal: AbortSignal.timeout(15000) })
    const j = r.ok ? await r.json() : null
    return { ok: !!j && ['none', 'minor'].includes(j.status?.indicator), code: r.status, ms: Date.now() - t0 }
  }
  if (it.kind === 'hc') {
    const c = (await loadHc())[it.slug]
    if (c && (c.status === 'new' || c.status === 'paused')) return { nodata: true, ok: false, code: 0, ms: 0 }   // még nem pingelt / szüneteltetett → nincs adat, nem kiesés
    return { ok: !!c && (c.status === 'up' || c.status === 'grace'), code: c ? ({ up: 200, grace: 200, down: 503, new: 404, paused: 410 }[c.status] || 0) : 404, ms: Date.now() - t0 }
  }
  if (it.kind === 'r2') {
    const r = await r2('GET', 'monitor', 'monitor.json')
    return { ok: r.status === 200 || r.status === 404, code: r.status, ms: Date.now() - t0 }
  }
  throw new Error('ismeretlen kind: ' + it.kind)
}

async function probe(it) {
  let last = { ok: false, code: 0, ms: 0 }
  for (let i = 0; i < 3; i++) {                       // 1 mérés + 2 újrapróba, 10 mp szünettel
    try { last = await probeOnce(it) } catch { last = { ok: false, code: 0, ms: 0 } }
    if (last.ok || last.nodata) return last
    if (i < 2) await sleep(DRY ? 1500 : 10000)
  }
  return last
}

const dueNow = (it, now) => {
  const d = new Date(now)
  if (it.cadence === 'hourly') return d.getUTCMinutes() < 10
  if (it.cadence === 'daily') return d.getUTCHours() === 2 && d.getUTCMinutes() < 10
  return true
}

// ─── fő ─────────────────────────────────────────────────────────────────────────
const now = Date.now()
const prev = DRY && !ACCT ? null : await r2Json('monitor', 'monitor.json')
const prevItems = {}
for (const a of prev?.apps || []) for (const i of a.items) prevItems[i.id] = i
const raw = prev?.raw || {}

const month = localDay(now).slice(0, 7)
const daily = (DRY && !ACCT ? null : await r2Json('monitor', `daily/${month}.json`)) || {}

const flat = cfg.apps.flatMap((a) => a.items.map((i) => ({ app: a, it: i })))
const results = await Promise.all(flat.map(async ({ it }) => (dueNow(it, now) ? [it.id, await probe(it)] : [it.id, null])))
const res = Object.fromEntries(results)

const apps = cfg.apps.map((a) => ({
  id: a.id, name: a.name,
  items: a.items.map((it) => {
    const p = prevItems[it.id] || {}
    const m = res[it.id]
    if (m?.nodata) return { id: it.id, name: it.name, kind: it.kind, cadence: it.cadence, state: 'nodata', lastOkAt: p.lastOkAt || null, lastMs: null, lastCode: null, checkedAt: now, failRunStart: null }
    const out = { id: it.id, name: it.name, kind: it.kind, cadence: it.cadence, state: p.state || 'unknown', lastOkAt: p.lastOkAt || null, lastMs: p.lastMs ?? null, lastCode: p.lastCode ?? null, checkedAt: p.checkedAt || null, failRunStart: p.failRunStart || null }
    if (!m) return out                                 // carry-forward: utolsó ismert érték + checkedAt
    out.state = m.ok ? 'ok' : 'fail'; out.lastMs = m.ms; out.lastCode = m.code; out.checkedAt = now
    if (m.ok) { out.lastOkAt = now; out.failRunStart = null } else if (!out.failRunStart) out.failRunStart = now
    // nyers 48 óra
    ;(raw[it.id] ||= []).push([now, m.ok ? 1 : 0, m.ms, m.code])
    raw[it.id] = raw[it.id].filter((s) => s[0] >= now - RAW_KEEP_MS)
    // napi összesítés
    const day = ((daily[it.id] ||= {})[localDay(now)] ||= { n: 0, fail: 0, maxRunMin: 0, incidents: [] })
    day.n++
    if (!m.ok) {
      day.fail++
      const runMin = Math.round((now - out.failRunStart) / 6e4) + SLOT_MIN
      day.maxRunMin = Math.max(day.maxRunMin, runMin)
      const last = day.incidents[day.incidents.length - 1]
      if (last && now - last[1] <= (SLOT_MIN + 5) * 6e4) last[1] = now
      else day.incidents.push([now, now])
    }
    return out
  }),
}))
for (const k of Object.keys(raw)) if (!flat.some((f) => f.it.id === k)) delete raw[k]

const monitor = { updatedAt: now, runId: process.env.RUN_ID || 'local', apps, raw }

// nyilvános, szűrt másolat: csak név + állapot + időpont (nincs URL, kód, hibaüzenet)
const pub = { updatedAt: now, apps: apps.map((a) => ({ id: a.id, name: a.name, items: a.items.map((i) => ({ name: i.name, state: i.state, checkedAt: i.checkedAt })) })) }

await r2Put('monitor', 'monitor.json', monitor)
await r2Put('monitor', `daily/${month}.json`, daily)
await r2Put('monitor-public', 'monitor-public.json', pub)

// ─── összegzés + healthchecks ping ──────────────────────────────────────────────
const all = apps.flatMap((a) => a.items)
const failing = all.filter((i) => i.state === 'fail').map((i) => i.id)
const measured = Object.values(res).filter((m) => m && !m.nodata).length
console.log(`mérve: ${measured}/${all.length}, hibás: ${failing.length ? failing.join(', ') : '-'}`)
for (const [id, m] of Object.entries(res)) if (m) console.log(`${m.nodata ? 'N/A ' : m.ok ? 'OK  ' : 'FAIL'} ${id} ${m.code} ${m.ms}ms`)

if (!DRY && process.env.HC_PING_URL) {
  const body = JSON.stringify({ ok: all.length - failing.length, total: all.length, failing })
  try { await fetch(process.env.HC_PING_URL, { method: 'POST', body, signal: AbortSignal.timeout(15000) }) } catch { console.log('healthchecks ping nem ment el') }
}
