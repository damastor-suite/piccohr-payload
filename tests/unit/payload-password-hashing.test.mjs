import assert from 'node:assert/strict'
import crypto from 'node:crypto'
import { afterEach, test } from 'node:test'

const hashingURL = new URL(
  './auth/strategies/local/generatePasswordSaltHash.js',
  import.meta.resolve('payload'),
)
const { authenticateLocalStrategy } = await import(
  new URL('./auth/strategies/local/authenticate.js', import.meta.resolve('payload'))
)
const originalNavigator = Object.getOwnPropertyDescriptor(globalThis, 'navigator')
const originalPbkdf2 = crypto.pbkdf2
let importCount = 0

afterEach(() => {
  crypto.pbkdf2 = originalPbkdf2
  if (originalNavigator) {
    Object.defineProperty(globalThis, 'navigator', originalNavigator)
  } else {
    delete globalThis.navigator
  }
})

async function loadHashing(userAgent) {
  Object.defineProperty(globalThis, 'navigator', {
    configurable: true,
    value: { userAgent },
  })
  return import(`${hashingURL.href}?runtime=${++importCount}`)
}

function enforceWorkersLimit() {
  crypto.pbkdf2 = (password, salt, iterations, keyLength, digest, callback) => {
    assert.ok(iterations <= 100000, `Workers rejects ${iterations} PBKDF2 iterations`)
    return originalPbkdf2(password, salt, iterations, keyLength, digest, callback)
  }
}

async function generate(hashing) {
  return hashing.generatePasswordSaltHash({
    collection: { slug: 'users' },
    isPasswordAuthenticated: true,
    password: 'registration-test-password',
    req: {},
  })
}

test('Workers registration and login stay within the PBKDF2 cap', async () => {
  const hashing = await loadHashing('Cloudflare-Workers')
  enforceWorkersLimit()
  const doc = { id: 1, ...(await generate(hashing)) }
  assert.match(doc.hash, /^pbkdf2-sha256-v2-i100000-l32:[0-9a-f]{64}$/)
  assert.equal(doc.salt.length, 64)
  assert.deepEqual(
    await authenticateLocalStrategy({ doc, password: 'registration-test-password' }),
    { doc, shouldUpdatePasswordHash: false },
  )
  assert.equal(await authenticateLocalStrategy({ doc, password: 'wrong-password' }), null)
})

test('Workers-created passwords also authenticate in Node', async () => {
  const workersHashing = await loadHashing('Cloudflare-Workers')
  const doc = { id: 1, ...(await generate(workersHashing)) }
  const nodeHashing = await loadHashing('Node.js')
  assert.equal(nodeHashing.getPasswordHashParameters(doc.hash).iterations, 100000)
  assert.deepEqual(
    await authenticateLocalStrategy({ doc, password: 'registration-test-password' }),
    { doc, shouldUpdatePasswordHash: false },
  )
})

test('Node keeps 600000 iterations and can authenticate new passwords', async () => {
  const hashing = await loadHashing('Node.js')
  const doc = { id: 1, ...(await generate(hashing)) }
  assert.match(doc.hash, /^pbkdf2-sha256-v2-i600000-l32:[0-9a-f]{64}$/)
  assert.deepEqual(
    await authenticateLocalStrategy({ doc, password: 'registration-test-password' }),
    { doc, shouldUpdatePasswordHash: false },
  )
})

test('existing v1 hashes retain 600000 iterations and request migration on Node login', async () => {
  const hashing = await loadHashing('Node.js')
  const salt = crypto.randomBytes(32).toString('hex')
  const rawHash = crypto.pbkdf2Sync('existing-password', salt, 600000, 32, 'sha256')
  const doc = { id: 1, salt, hash: `pbkdf2-sha256-v1:${rawHash.toString('hex')}` }
  assert.equal(hashing.getPasswordHashParameters(doc.hash).iterations, 600000)
  assert.deepEqual(await authenticateLocalStrategy({ doc, password: 'existing-password' }), {
    doc,
    shouldUpdatePasswordHash: true,
  })
})

test('legacy passwords authenticate on Workers and request migration', async () => {
  await loadHashing('Cloudflare-Workers')
  const salt = crypto.randomBytes(32).toString('hex')
  const hash = crypto.pbkdf2Sync('legacy-password', salt, 25000, 512, 'sha256').toString('hex')
  const doc = { id: 1, salt, hash }
  enforceWorkersLimit()
  assert.deepEqual(await authenticateLocalStrategy({ doc, password: 'legacy-password' }), {
    doc,
    shouldUpdatePasswordHash: true,
  })
})

test('malformed or unsupported hashes fail authentication', async () => {
  for (const hash of [
    'pbkdf2-sha256-v2-i0-l32:' + '0'.repeat(64),
    'pbkdf2-sha256-v2-i999999999-l32:' + '0'.repeat(64),
    'pbkdf2-sha256-v2-i100000-l999999999:' + '0'.repeat(64),
    'pbkdf2-sha256-v2-i100000-l32:invalid',
  ]) {
    assert.equal(
      await authenticateLocalStrategy({
        doc: { id: 1, salt: 'test-salt', hash },
        password: 'test',
      }),
      null,
    )
  }
})
