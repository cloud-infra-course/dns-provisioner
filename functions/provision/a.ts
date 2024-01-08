import { verifyIdToken, verifyUserInCanvasCourse } from '../auth'

interface Env {
  GOOGLE_CLIENT_ID: string
  CLOUDFLARE_EMAIL: string
  CLOUDFLARE_KEY: string
  CLOUDFLARE_TOKEN: string
  CLOUDFLARE_ZONE_ID: string
  CANVAS_API_TOKEN: string
  CANVAS_COURSE_ID: string
}

interface ProvisionerInput {
  ip: string
}

interface DnsResult {
  content: string
  name: string
  type: string
  id: string
}

interface DnsListResponse {
  success: boolean
  errors: any[]
  result: DnsResult[]
}

function isProvisionerInput (data: unknown): data is ProvisionerInput {
  const test = data as ProvisionerInput
  if (test.ip === undefined) {
    return false
  }

  const ipv4Regex: RegExp = /^((?:[0-9]|[1-9][0-9]|1[0-9][0-9]|2[0-4][0-9]|25[0-5])[.]){3}(?:[0-9]|[1-9][0-9]|1[0-9][0-9]|2[0-4][0-9]|25[0-5])$/
  if (!ipv4Regex.test(test.ip)) {
      return false
  }

  return true
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

async function createRecords (env: Env, zoneId: string, sunet: string, ip: string): Promise<void> {
  await fetch(
    `https://api.cloudflare.com/client/v4/zones/${env.CLOUDFLARE_ZONE_ID}/dns_records`,
    {
      method: 'POST',
      headers: {
        Authorization: `Bearer ${env.CLOUDFLARE_TOKEN}`,
        'X-Auth-Email': env.CLOUDFLARE_EMAIL,
        'X-Auth-Key': env.CLOUDFLARE_KEY,
      },
      body: JSON.stringify({
        type: 'A',
        name: `a1.${sunet}`,
        content: ip,
      }),
    },
  )
}

export const onRequest: PagesFunction<Env> = async (context) => {
  if (context.request.method !== 'POST') {
    return new Response(null, { status: 405, statusText: 'Method not allowed' })
  }

  const zoneId = context.env.CLOUDFLARE_ZONE_ID
  if (zoneId === undefined) {
    return new Response(null, { status: 500, statusText: 'Internal server error' })
  }

  const sunet = await authenticate(context)
  if (sunet === null) {
    return new Response(null, { status: 403, statusText: 'Unauthorized' })
  }

  const input = await context.request.json()
  if (!isProvisionerInput(input)) {
    return new Response(null, {
      status: 400,
      statusText: 'Malformed input',
    })
  }

  const response = await fetch(
    `https://api.cloudflare.com/client/v4/zones/${zoneId}/dns_records?name=${sunet}.infracourse.cloud&type=A`, {
      headers: {
        Authorization: `Bearer ${context.env.CLOUDFLARE_TOKEN}`,
        'X-Auth-Email': context.env.CLOUDFLARE_EMAIL,
        'X-Auth-Key': context.env.CLOUDFLARE_KEY,
      },
    },
  )

  const records: DnsListResponse = await response.json()
  let statusCode = 201

  if (records.result !== null) {
    for (const record of records.result) {
      const deleteResponse = await fetch(
        `https://api.cloudflare.com/client/v4/zones/${zoneId}/dns_records/${record.id}`,
        {
          method: 'DELETE',
          headers: {
            Authorization: `Bearer ${context.env.CLOUDFLARE_TOKEN}`,
            'X-Auth-Email': context.env.CLOUDFLARE_EMAIL,
            'X-Auth-Key': context.env.CLOUDFLARE_KEY,
          },
        },
      )

      if (!deleteResponse.ok) {
        return new Response(null, { status: 500, statusText: 'Internal server error' })
      }
    }
    statusCode = 204
  }

  await createRecords(context.env, zoneId, sunet, input.ip)

  return new Response(null, { status: statusCode })
}
