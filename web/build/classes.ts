/** Fits cn's class conflict tables to the fixed class names used by this page.
 * Component styles stay in the vendored primitives; the existing cn engine still performs merging.
 * Read classTables; generating smaller tables avoids shipping unrelated Tailwind class groups. */
import path from 'node:path'
import { build } from 'cn/build'
import type { Plugin } from 'vite'

/** Creates finite build-time tables, shared by production builds and component tests. */
export function classTables(): Plugin {
  const runtimeId = '\0netmon:classes'
  const tablesId = '\0netmon:class-tables'
  let root = ''
  let source = ''
  return {
    name: 'netmon-class-tables',
    enforce: 'pre',
    configResolved(config) {
      root = config.root
    },
    async buildStart() {
      // API strings never supply classes, so every runtime class group comes from these sources.
      const result = await build({
        cwd: root,
        content: ['src/**/*.{ts,tsx}'],
        out: path.join(root, '.build/cn-tables.mjs'),
      })
      for (const warning of result.warnings) this.warn(warning)
      source = result.source
    },
    resolveId(id) {
      if (id === 'cn') return runtimeId
      if (id === 'netmon:class-tables') return tablesId
    },
    load(id) {
      if (id === tablesId) return source
      if (id === runtimeId)
        return `import { createCn } from 'cn/engine';
        import tables from 'netmon:class-tables'; export const cn = createCn(tables);`
    },
  }
}
