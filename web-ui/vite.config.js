import { fileURLToPath } from "node:url";
import { dirname, resolve } from "node:path";
import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";

const root = dirname(fileURLToPath(import.meta.url));

export default defineConfig({
  plugins: [react()],
  server: {
    host: "127.0.0.1",
    proxy: {
      // The backend rejects POSTs whose Origin is not itself (CSRF guard), so
      // present the dev server's requests as coming from the backend origin.
      "/api": {
        target: "http://127.0.0.1:8765",
        changeOrigin: true,
        headers: { origin: "http://127.0.0.1:8765" },
      },
    },
  },
  build: {
    outDir: resolve(root, "../securityops/web/dist"),
    emptyOutDir: true,
  },
});
