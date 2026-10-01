import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { MotionConfig } from 'framer-motion'
import { lazy, Suspense } from 'react'
import { BrowserRouter, Link, Route, Routes } from 'react-router-dom'
import { ApiError } from './api/client'
import { RequireAuth } from './app/RequireAuth'
import Landing from './landing/Landing'

const Login = lazy(() => import('./app/Login'))
const ConsoleLayout = lazy(() => import('./app/ConsoleLayout'))
const Incidents = lazy(() => import('./app/pages/Incidents'))
const Compliance = lazy(() => import('./app/pages/Compliance'))
const Adversary = lazy(() => import('./app/pages/Adversary'))
const Evaluation = lazy(() => import('./app/pages/Evaluation'))
const Runs = lazy(() => import('./app/pages/Runs'))
const Assets = lazy(() => import('./app/pages/Assets'))
const Audit = lazy(() => import('./app/pages/Audit'))

const queryClient = new QueryClient({
  defaultOptions: {
    queries: {
      staleTime: 30_000,
      refetchOnWindowFocus: false,
      // 4xx answers will not change on retry; network blips and 5xx might.
      retry: (n, err) => !(err instanceof ApiError && err.status >= 400 && err.status < 500) && n < 2,
    },
  },
})

function NotFound() {
  return (
    <main className="not-found">
      <h1>Nothing at this address</h1>
      <p>
        <Link to="/">Go to the Prahari home page</Link> or <Link to="/console">open the console</Link>.
      </p>
    </main>
  )
}

export default function App() {
  return (
    <QueryClientProvider client={queryClient}>
      <MotionConfig reducedMotion="user">
        <BrowserRouter>
          <Suspense fallback={<div className="route-loading" aria-busy="true" />}>
            <Routes>
              <Route path="/" element={<Landing />} />
              <Route path="/login" element={<Login />} />
              <Route path="/console" element={<RequireAuth><ConsoleLayout /></RequireAuth>}>
                <Route index element={<Incidents />} />
                <Route path="compliance" element={<Compliance />} />
                <Route path="compliance/:caseId" element={<Compliance />} />
                <Route path="adversary" element={<Adversary />} />
                <Route path="evaluation" element={<Evaluation />} />
                <Route path="runs" element={<Runs />} />
                <Route path="assets" element={<Assets />} />
                <Route path="audit" element={<Audit />} />
                <Route path=":id" element={<Incidents />} />
              </Route>
              <Route path="*" element={<NotFound />} />
            </Routes>
          </Suspense>
        </BrowserRouter>
      </MotionConfig>
    </QueryClientProvider>
  )
}
