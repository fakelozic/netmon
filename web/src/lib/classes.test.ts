/** Checks the project-fitted merge tables against cn's complete default tables.
 * Build-time table generation belongs to build/classes.ts; primitives stay unmodified.
 * Read the parity cases for variant conflicts, arbitrary values and custom protocol classes. */
import { cn } from 'cn'
import { createCn } from 'cn/engine'
import tables from 'cn/tables'
import { expect, it } from 'vitest'

const full = createCn(tables)
it.each([
  ['h-8 px-2.5 text-sm', 'h-7 px-2 text-xs'],
  ['flex h-full w-full', 'flex-1 min-h-0'],
  ['bg-primary text-primary-foreground', 'bg-background text-muted-foreground'],
  ['focus-visible:ring-3 focus-visible:ring-ring/50', 'focus-visible:ring-1'],
  ['w-72 rounded-lg', 'w-[500px] rounded-none'],
  ['proto-tcp selected-row', 'packet-columns packet-row'],
])('preserves default merging for %s / %s', (first, second) => {
  expect(cn(first, second)).toBe(full(first, second))
  expect(cn([first], { [second]: true }, null, false)).toBe(
    full([first], { [second]: true }, null, false),
  )
})
