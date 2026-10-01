import { useSyncExternalStore } from 'react'
import { getToken, onTokenChange } from './client'

/** The current bearer token; re-renders when it is set, cleared, or rejected with a 401. */
export function useToken() {
  return useSyncExternalStore(onTokenChange, getToken, () => null)
}
