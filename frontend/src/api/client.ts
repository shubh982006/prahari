// Thin typed client for the Prahari API. Types come from schema.d.ts, which is
// generated from backend/api/openapi.yaml (`npm run gen:api`).

import type { components } from './schema'

export type Schemas = components['schemas']

// Where the API lives. Empty means same origin (the Vite proxy in development,
// or nginx in front of both); set VITE_API_BASE at build time when the API is
// on another origin, e.g. https://prahari-api.onrender.com.
const ORIGIN = (import.meta.env.VITE_API_BASE ?? '').replace(/\/+$/, '')
const BASE = ORIGIN + '/api/v1'

/** Absolute URL for an API path, for callers that cannot use api(): EventSource, raw fetches. */
export function apiUrl(path: string) {
  return BASE + path
}
const TOKEN_KEY = 'prahari.token'

let token: string | null = readToken()
const listeners = new Set<() => void>()

function readToken(): string | null {
  try {
    return sessionStorage.getItem(TOKEN_KEY)
  } catch {
    return null
  }
}

export function getToken() {
  return token
}

export function setToken(next: string | null) {
  token = next
  try {
    if (next) sessionStorage.setItem(TOKEN_KEY, next)
    else sessionStorage.removeItem(TOKEN_KEY)
  } catch {
    /* storage blocked: the token lives for this tab only */
  }
  listeners.forEach((l) => l())
}

/** Called whenever the token changes, including when a 401 clears it. */
export function onTokenChange(fn: () => void) {
  listeners.add(fn)
  return () => {
    listeners.delete(fn)
  }
}

/** RFC 7807 problem, as every non-2xx response from the API is shaped. */
export class ApiError extends Error {
  status: number
  code: string
  detail: string
  requestId?: string
  problem: Partial<Schemas['Problem']> | null

  constructor(status: number, problem: Partial<Schemas['Problem']> | null, fallback: string) {
    const fields = problem?.errors?.map((e) => `${e.field.replace(/^body\./, '')} ${e.message}`).join('; ')
    super(fields || problem?.detail || problem?.title || fallback)
    this.status = status
    this.code = problem?.code ?? 'HTTP_' + status
    this.detail = problem?.detail ?? fallback
    this.requestId = problem?.request_id
    this.problem = problem
  }
}

type Query = Record<string, string | number | boolean | undefined | null>

function url(path: string, query?: Query) {
  const qs = new URLSearchParams()
  for (const [k, v] of Object.entries(query ?? {})) {
    if (v !== undefined && v !== null && v !== '') qs.set(k, String(v))
  }
  const s = qs.toString()
  return BASE + path + (s ? '?' + s : '')
}

export async function api<T>(
  path: string,
  opts: { method?: string; query?: Query; body?: unknown; headers?: Record<string, string>; signal?: AbortSignal } = {},
): Promise<T> {
  const headers: Record<string, string> = { Accept: 'application/json', ...opts.headers }
  if (token) headers.Authorization = `Bearer ${token}`
  if (opts.body !== undefined) headers['Content-Type'] = 'application/json'

  let res: Response
  try {
    res = await fetch(url(path, opts.query), {
      method: opts.method ?? 'GET',
      headers,
      body: opts.body === undefined ? undefined : JSON.stringify(opts.body),
      signal: opts.signal,
    })
  } catch (e) {
    if ((e as Error).name === 'AbortError') throw e
    throw new ApiError(0, null, ORIGIN ? `Cannot reach the Prahari API at ${ORIGIN}.` : 'Cannot reach the Prahari API. Is the backend running?')
  }

  if (res.status === 401 && path !== '/auth/login') setToken(null)
  if (res.status === 204) return undefined as T
  const text = await res.text()
  const data = text ? safeJson(text) : null
  if (!res.ok) throw new ApiError(res.status, data as Partial<Schemas['Problem']> | null, `${res.status} ${res.statusText}`)
  return data as T
}

function safeJson(text: string): unknown {
  try {
    return JSON.parse(text)
  } catch {
    return null
  }
}

export function login(username: string, password: string) {
  return api<Schemas['LoginResponse']>('/auth/login', { method: 'POST', body: { username, password } })
}
