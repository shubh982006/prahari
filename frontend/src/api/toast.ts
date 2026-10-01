import { useSyncExternalStore } from 'react'

export interface Toast {
  id: number
  tone: 'info' | 'success' | 'alert' | 'error'
  title: string
  body?: string
  href?: string
}

let toasts: Toast[] = []
let seq = 0
const subs = new Set<() => void>()
const emit = () => subs.forEach((f) => f())

export function toast(t: Omit<Toast, 'id'>) {
  const id = ++seq
  toasts = [...toasts, { ...t, id }].slice(-4)
  emit()
  window.setTimeout(() => dismiss(id), t.tone === 'error' || t.tone === 'alert' ? 8000 : 4500)
}

export function dismiss(id: number) {
  toasts = toasts.filter((t) => t.id !== id)
  emit()
}

export function useToasts() {
  return useSyncExternalStore(
    (f) => {
      subs.add(f)
      return () => {
        subs.delete(f)
      }
    },
    () => toasts,
    () => toasts,
  )
}
