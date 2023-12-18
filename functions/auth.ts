import { decodeProtectedHeader, jwtVerify, importX509, type JWTPayload, type KeyLike } from 'jose'
const inFlight = new Map<string, Promise<KeyLike>>()
const cache = new Map<string, CacheVal>()

interface ImportPublicKeyOptions {
  keyId: string
  certificateURL: string | undefined
  waitUntil: ((promise: Promise<any>) => void) | undefined
}

interface VerifyIdTokenOptions {
  idToken: string | undefined
  clientId: string | undefined
  waitUntil: ((promise: Promise<any>) => void) | undefined
}

interface CacheVal {
  key: KeyLike
  expires: number
}

interface CanvasUser {
  login_id: string
}

/**
 * Imports a public key for the provided Google Cloud (GCP)
 * service account credentials.
 *
 * @throws {FetchError} - If the X.509 certificate could not be fetched.
 */
async function importPublicKey (options: ImportPublicKeyOptions): Promise<KeyLike> {
  const keyId = options.keyId
  const certificateURL = options.certificateURL ?? 'https://www.googleapis.com/robot/v1/metadata/x509/securetoken@system.gserviceaccount.com' // prettier-ignore
  const cacheKey = `${certificateURL}?key=${keyId}`
  const value = cache.get(cacheKey)
  const now = Date.now()
  async function fetchKey (): Promise<KeyLike> {
    // Fetch the public key from Google's servers
    const res = await fetch(certificateURL)
    if (!res.ok) {
      throw new Error('Failed to fetch the public key')
    }
    const data: Record<string, string> = await res.json()
    const x509 = data[keyId]
    if (x509 === undefined) {
      throw new Error(`Public key "${keyId}" not found.`)
    }
    const key = await importX509(x509, 'RS256')
    // Resolve the expiration time of the key
    const maxAge = res.headers.get('cache-control')?.match(/max-age=(\d+)/)?.[1] // prettier-ignore
    const expires = Date.now() + Number(maxAge ?? '3600') * 1000
    // Update the local cache
    cache.set(cacheKey, { key, expires })
    if (keyId === undefined) {
      throw new Error('Missing KeyId')
    }
    inFlight.delete(keyId)
    return key
  }
  // Attempt to read the key from the local cache
  if (value !== undefined) {
    if (value.expires > now + 10_000) {
      // If the key is about to expire, start a new request in the background
      if (value.expires - now < 600_000) {
        const promise = fetchKey()
        inFlight.set(cacheKey, promise)
        if (options.waitUntil !== undefined) {
          options.waitUntil(promise)
        }
      }
      return value.key
    } else {
      cache.delete(cacheKey)
    }
  }
  // Check if there is an in-flight request for the same key ID
  let promise = inFlight.get(cacheKey)
  // If not, start a new request
  if (promise === undefined) {
    promise = fetchKey()
    inFlight.set(cacheKey, promise)
  }
  return await promise
}

// based on https://www.npmjs.com/package/web-auth-library?activeTab=code
// made to check per Google's recommendations: https://developers.google.com/identity/gsi/web/guides/verify-google-id-token
export async function verifyIdToken (options: VerifyIdTokenOptions): Promise<JWTPayload> {
  if (options.idToken === undefined) {
    throw new TypeError('Missing "idToken"')
  }
  const clientId = options?.clientId
  if (clientId === undefined) {
    throw new TypeError('Missing "clientId"')
  }
  if (options.waitUntil == null) {
    console.warn('Missing `waitUntil` option.')
  }
  // Import the public key from the Google Cloud project
  const header = decodeProtectedHeader(options.idToken)
  if (header.kid === undefined) {
    throw new TypeError('Missing "idToken"')
  }
  const now = Math.floor(Date.now() / 1000)
  const key = await importPublicKey({
    keyId: header.kid,
    certificateURL: 'https://www.googleapis.com/oauth2/v1/certs',
    waitUntil: options.waitUntil,
  })
  const { payload } = await jwtVerify(options.idToken, key, {
    audience: clientId,
    issuer: ['https://accounts.google.com', 'accounts.google.com'],
    maxTokenAge: '1h',
    clockTolerance: '5m',
  })
  if (payload.sub === undefined) {
    throw new Error('Missing "sub" claim')
  }
  if (typeof payload.auth_time === 'number' && payload.auth_time > now) {
    throw new Error('Unexpected "auth_time" claim value')
  }
  return payload
}

export async function verifyUserInCanvasCourse(courseId: string, loginId: string, apiKey: string): Promise<boolean> {
  const response = await fetch(
    `https://canvas.stanford.edu/api/v1/courses/${courseId}/search_users?` + new URLSearchParams({
      search_term: loginId,
    }),
    {
      headers: {
        Authorization: `Bearer ${apiKey}`
      }
    }
  )

  const users: CanvasUser[] = await response.json()
  for (const user of users) {
    if (user.login_id == loginId) {
      return true
    }
  }

  return false
}