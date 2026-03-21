/// <reference types="vite/client" />

interface ImportMetaEnv {
  readonly VITE_GH_TOKEN: string
  readonly VITE_GH_OWNER: string
  readonly VITE_GH_REPO: string
}

interface ImportMeta {
  readonly env: ImportMetaEnv
}
