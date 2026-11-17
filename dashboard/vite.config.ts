import { defineConfig } from 'vite';
import { viteSingleFile } from 'vite-plugin-singlefile';

export default defineConfig({
  plugins: [viteSingleFile()],
  build: {
    outDir: 'dist',
    emptyOutDir: true,
    rollupOptions: {
      input: 'CxOne_Audit_Log_Dashboard.html',
    },
  },
  test: {
    globals: true,
    environment: 'node',
  },
});
