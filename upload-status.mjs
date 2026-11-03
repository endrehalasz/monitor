// Egyszeri feltöltés: status.html → monitor-public/<PUBLIC_PREFIX>/status.html (R2). Futtatás: node upload-status.mjs (R2_* + PUBLIC_PREFIX env)
import crypto from 'node:crypto'
import fs from 'node:fs'
const sha = (d) => crypto.createHash('sha256').update(d).digest('hex')
const hm = (k, d) => crypto.createHmac('sha256', k).update(d).digest()
const { R2_ACCOUNT_ID: A, R2_ACCESS_KEY_ID: K, R2_SECRET_ACCESS_KEY: S, PUBLIC_PREFIX: P } = process.env
if (!A || !K || !S || !P) throw new Error('env hiányzik')
const body = fs.readFileSync(new URL('./status.html', import.meta.url))
const host = `${A}.r2.cloudflarestorage.com`, path = `/monitor-public/${P}/status.html`, ph = sha(body)
const amz = new Date().toISOString().replace(/[:-]|\.\d{3}/g, ''), date = amz.slice(0, 8)
const h = { 'cache-control': 'no-cache', 'content-type': 'text/html; charset=utf-8', host, 'x-amz-content-sha256': ph, 'x-amz-date': amz }
const n = Object.keys(h).sort()
const canon = ['PUT', path, '', n.map((x) => `${x}:${h[x]}\n`).join(''), n.join(';'), ph].join('\n')
const scope = `${date}/auto/s3/aws4_request`
const sts = ['AWS4-HMAC-SHA256', amz, scope, sha(canon)].join('\n')
const sig = crypto.createHmac('sha256', hm(hm(hm(hm('AWS4' + S, date), 'auto'), 's3'), 'aws4_request')).update(sts).digest('hex')
const r = await fetch(`https://${host}${path}`, { method: 'PUT', body, headers: { ...h, authorization: `AWS4-HMAC-SHA256 Credential=${K}/${scope}, SignedHeaders=${n.join(';')}, Signature=${sig}` } })
console.log('status.html feltöltve:', r.status)
