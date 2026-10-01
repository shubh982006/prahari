import type { ReactNode } from 'react'
import { Navigate, useLocation } from 'react-router-dom'
import { useToken } from '../api/useToken'

export function RequireAuth({ children }: { children: ReactNode }) {
  const token = useToken()
  const loc = useLocation()
  if (!token) return <Navigate to={`/login?next=${encodeURIComponent(loc.pathname + loc.search)}`} replace />
  return <>{children}</>
}
