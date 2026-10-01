import { ArrowRight, Eye, EyeSlash, WarningCircle } from '@phosphor-icons/react'
import { useQueryClient } from '@tanstack/react-query'
import { useEffect, useState, type FormEvent } from 'react'
import { Link, Navigate, useNavigate, useSearchParams } from 'react-router-dom'
import { ApiError, login, setToken } from '../api/client'
import { useToken } from '../api/useToken'
import { Logo } from '../components/Logo'
import './login.css'

export default function Login() {
  const token = useToken()
  const [params] = useSearchParams()
  const next = params.get('next')?.startsWith('/') ? params.get('next')! : '/console'
  const navigate = useNavigate()
  const qc = useQueryClient()
  const [username, setUsername] = useState('')
  const [password, setPassword] = useState('')
  const [show, setShow] = useState(false)
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState<string | null>(null)
  const [slow, setSlow] = useState(false)

  // A free host sleeps when idle; the first request can take a minute to wake it.
  useEffect(() => {
    if (!busy) return
    const t = window.setTimeout(() => setSlow(true), 4000)
    return () => {
      window.clearTimeout(t)
      setSlow(false)
    }
  }, [busy])

  if (token) return <Navigate to={next} replace />

  const submit = async (e: FormEvent) => {
    e.preventDefault()
    setBusy(true)
    setError(null)
    try {
      const res = await login(username.trim(), password)
      qc.clear()
      setToken(res.access_token)
      navigate(next, { replace: true })
    } catch (err) {
      const status = err instanceof ApiError ? err.status : 0
      setError(
        status === 401
          ? 'That username and password do not match an account.'
          : status === 429
            ? 'Too many attempts. Wait a minute, then try again.'
            : (err as Error).message,
      )
    } finally {
      setBusy(false)
    }
  }

  return (
    <main className="login">
      <div className="login__card">
        <Logo />
        <h1>Sign in to the console</h1>
        <form onSubmit={submit} noValidate>
          <label htmlFor="u">Username</label>
          <input id="u" name="username" autoComplete="username" value={username} onChange={(e) => setUsername(e.target.value)} required autoFocus />
          <label htmlFor="p">Password</label>
          <div className="login__pw">
            <input
              id="p"
              name="password"
              type={show ? 'text' : 'password'}
              autoComplete="current-password"
              value={password}
              onChange={(e) => setPassword(e.target.value)}
              required
            />
            <button type="button" onClick={() => setShow((s) => !s)} aria-label={show ? 'Hide password' : 'Show password'}>
              {show ? <EyeSlash size={18} /> : <Eye size={18} />}
            </button>
          </div>
          {error && (
            <p className="login__error" role="alert">
              <WarningCircle size={16} weight="fill" aria-hidden /> {error}
            </p>
          )}
          {slow && (
            <p className="login__slow" role="status">
              Waking the server. The free host sleeps after 15 quiet minutes, so the first sign-in can take up to a minute.
            </p>
          )}
          <button type="submit" className="btn btn--primary login__submit" disabled={busy || !username || !password}>
            <span>{busy ? 'Signing in…' : 'Sign in'}</span>
            {!busy && <ArrowRight size={16} weight="bold" aria-hidden />}
          </button>
        </form>
        <p className="login__demo">
          A backend started in demo mode accepts <code>meow</code> / <code>prahari-lead</code> (lead) and <code>analyst</code> /{' '}
          <code>prahari-analyst</code>. Outside demo mode these accounts do not exist.
        </p>
        <Link to="/" className="login__back">
          Back to the site
        </Link>
      </div>
    </main>
  )
}
