/// <reference types="vite/client" />

interface ImportMetaEnv {
  /** Origin of the Prahari API when it is not served from the same origin, e.g. https://prahari-api.onrender.com */
  readonly VITE_API_BASE?: string
}

interface ImportMeta {
  readonly env: ImportMetaEnv
}
