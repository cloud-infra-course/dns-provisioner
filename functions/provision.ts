import { verifyIdToken } from './oauth'

interface Env {
  GOOGLE_CLIENT_ID: string
  CLOUDFLARE_EMAIL: string
  CLOUDFLARE_KEY: string
  CLOUDFLARE_TOKEN: string
  CLOUDFLARE_ZONE_ID: string
}

interface ProvisionerInput {
  nameservers: string[]
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
  if (test.nameservers === undefined) {
    return false
  }

  const awsNsRegex: RegExp = /^ns-(?:[0-9]|[1-9][0-9]|[1-9][0-9]{2}|1[0-9]{3}|20[0-3][0-9]|204[0-7]).awsdns-(?:0[0-9]|[1-5][0-9]|6[0-3])?.(?:com|net|org|co.uk)(?:.)?$/
  for (const ns of test.nameservers) {
    if (!awsNsRegex.test(ns)) {
      return false
    }
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

  return username
}

async function createRecords (env: Env, zoneId: string, sunet: string, nameservers: string[]): Promise<void> {
  for (const ns of nameservers) {
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
          type: 'NS',
          name: sunet,
          content: ns,
        }),
      },
    )
  }
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
    `https://api.cloudflare.com/client/v4/zones/${zoneId}/dns_records?name=${sunet}.infracourse.cloud&type=NS`, {
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

  await createRecords(context.env, zoneId, sunet, input.nameservers)

  return new Response(null, { status: statusCode })
}
