import { defineConfig, type Plugin } from 'vite';
import { viteSingleFile } from 'vite-plugin-singlefile';

const toLf = (s: string) => s.replace(/\r\n?/g, '\n');

/**
 * Build from LF sources regardless of how they are checked out, so the committed web/ file
 * is byte-identical to a Linux (CI) build. On Windows with core.autocrlf=true the .html,
 * .css and .ts sources have CRLF; normalizing the *output* isn't enough, because Vite strips
 * the <script>/<link> tags it inlines together with their "\n" but not the "\r".
 */
function lfSources(): Plugin {
  return {
    name: 'lf-sources',
    enforce: 'pre',
    transformIndexHtml: { order: 'pre', handler: toLf },
    transform(code, id) {
      if (/\.(m?[jt]s|css)(\?|$)/.test(id) && code.includes('\r')) return { code: toLf(code), map: null };
      return null;
    },
  };
}

export default defineConfig({
  plugins: [lfSources(), viteSingleFile()],
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
