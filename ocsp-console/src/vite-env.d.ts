/// <reference types="vite/client" />

interface ImportMetaEnv {
  /** Dev only: OAuth2 client used to fetch a token from local ocsp-auth. */
  readonly VITE_DEV_CLIENT_ID?: string
  readonly VITE_DEV_CLIENT_SECRET?: string
}

interface ImportMeta {
  readonly env: ImportMetaEnv
}
