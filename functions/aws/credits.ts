import { verifyIdToken, verifyUserInCanvasCourse } from '../auth'

interface Env {
  GOOGLE_CLIENT_ID: string
  CLOUDFLARE_EMAIL: string
  CLOUDFLARE_KEY: string
  CLOUDFLARE_TOKEN: string
  CLOUDFLARE_ZONE_ID: string
  CANVAS_API_TOKEN: string
  CANVAS_COURSE_ID: string
  CREDITS_KV: KVNamespace
}

interface CreditRecord {
    code: string
    viewed: boolean
}

// Verifies the provided Google JWT, and returns the user's SUNet ID if valid
async function authenticate (context: EventContext<Env, any, Record<string, unknown>>): Promise<string | null> {
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

  const creditCode = await context.env.CREDITS_KV.get(sunet)
  if (creditCode === null) {
      return new Response(null, { status: 404, statusText: 'Not found' })
  }

  let record = JSON.parse(creditCode) as CreditRecord
  record.viewed = true
  await context.env.CREDITS_KV.put(sunet, JSON.stringify(record))

  return new Response(JSON.stringify({ code: record.code }), { status: 200 })
}
