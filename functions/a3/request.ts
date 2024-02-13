import { verifyIdToken, verifyUserInCanvasCourse } from '../auth'

interface Env {
  GOOGLE_CLIENT_ID: string
  CLOUDFLARE_EMAIL: string
  CLOUDFLARE_KEY: string
  CLOUDFLARE_TOKEN: string
  CLOUDFLARE_ZONE_ID: string
  CANVAS_API_TOKEN: string
  CANVAS_COURSE_ID: string
  REQUESTS_KV: KVNamespace
}

interface RequestRecord {
  flag: string
  lastAccessed: Date
}

// Verifies the provided Google JWT, and returns the user's SUNet ID if valid
async function authenticate(context: EventContext<Env, any, Record<string, unknown>>): Promise<string | null> {
  const authHeader = context.request.headers.get('Authorization')
  if (authHeader === null) {
    return null
  }

  const [scheme, token] = authHeader.split(' ')
  if (scheme !== 'Bearer') {
    return null
  }

  const payload = await verifyIdToken({
    idToken: token,
    clientId: context.env.GOOGLE_CLIENT_ID,
    waitUntil: context.waitUntil,
  })

  if (typeof payload.email !== 'string' || typeof payload.hd !== 'string') {
    return null
  }

  const [username, domain] = payload.email.split('@')
  if (payload.hd !== 'stanford.edu' || domain !== 'stanford.edu') {
    return null
  }

  if (!await verifyUserInCanvasCourse(context.env.CANVAS_COURSE_ID, username, context.env.CANVAS_API_TOKEN)) {
    return null
  }

  return username
}

export const onRequest: PagesFunction<Env> = async (context) => {
  if (context.request.method !== 'GET') {
    return new Response(null, { status: 405, statusText: 'Method not allowed' })
  }

  const sunet = await authenticate(context)
  if (sunet === null) {
    return new Response(null, { status: 403, statusText: 'Unauthorized' })
  }

  const requestRecord = await context.env.REQUESTS_KV.get(sunet) || 'null'
  let record = JSON.parse(requestRecord) as RequestRecord

  if (record === null) {
    record = {
      flag: crypto.randomUUID(),
      lastAccessed: new Date()
    }
  }

  record.lastAccessed = new Date()

  await fetch(
    `https://yoctogram.${sunet}.infracourse.cloud/api/v1/this/is/a/really/long/path/that/should/error`, {
    headers: {
      'User-Agent': `CS40-Provisioner-Client (On Behalf Of ${sunet}, flag=${record.flag})`,
    }
  })

  await context.env.REQUESTS_KV.put(sunet, JSON.stringify(record))

  return new Response(null, { status: 200 })
}
