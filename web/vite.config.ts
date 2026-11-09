import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";
import tailwindcss from "@tailwindcss/vite";

// The Go server embeds internal/web/assets and serves it at "/", so the build
// writes straight into that directory. base "./" keeps the asset URLs relative
// to whichever path the control API is mounted on.
export default defineConfig({
  plugins: [react(), tailwindcss()],
  base: "./",
  resolve: {
    alias: { "@": new URL("./src", import.meta.url).pathname },
  },
  build: {
    // Nested inside the embedded tree: the Go server already serves
    // internal/web/assets at "/", so the new SPA is reachable at "/next/"
    // while the legacy dashboard keeps the root until the cutover.
    outDir: "../internal/web/assets/next",
    emptyOutDir: true,
    sourcemap: false,
  },
});
