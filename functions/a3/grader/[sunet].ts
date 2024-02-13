import { verifyIdToken, verifyUserInCanvasCourse } from '../../auth'

interface Env {
  REQUESTS_KV: KVNamespace
  GRADER_TOKEN: string
}

interface RequestRecord {
  flag: string
  lastAccessed: Date
}

export const onRequest: PagesFunction<Env> = async (context) => {
  if (context.request.method !== 'GET') {
    return new Response(null, { status: 405, statusText: 'Method not allowed' })
  }

  if (context.request.headers.get('X-Grader-Token') !== context.env.GRADER_TOKEN) {
    return new Response(null, { status: 403, statusText: 'Unauthorized' })
  }

  const { searchParams } = new URL(context.request.url)
  let flag = searchParams.get('flag')
  if (flag === null) {
    return new Response(null, { status: 400, statusText: 'Bad request' })
  }

  const sunet = context.params.sunet as string

  const requestRecord = await context.env.REQUESTS_KV.get(sunet)
  if (requestRecord === null) {
    return new Response(null, { status: 404, statusText: 'Not found' })
  }

  let record = JSON.parse(requestRecord) as RequestRecord
  if (flag !== record.flag) {
    return new Response(JSON.stringify({ correct: false }), { status: 200 })
  }

  return new Response(JSON.stringify({ correct: true }), { status: 200 })
}
