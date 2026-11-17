import { defineConfig } from 'vite';
import { viteSingleFile } from 'vite-plugin-singlefile';

export default defineConfig({
  plugins: [viteSingleFile()],
  build: {
    // Single self-contained HTML, written where `python main.py --serve` serves it from.
    // The same file also works standalone (open it in a browser and load an export).
    outDir: '../web',
    // web/ is outside this project root; never wipe it, just overwrite the one file.
    emptyOutDir: false,
    rollupOptions: {
      input: 'CxOne_Audit_Log_Dashboard.html',
    },
  },
  test: {
    globals: true,
    environment: 'node',
  },
});
