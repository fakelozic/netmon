/** Submits a display filter without replacing the user's text after an error.
 * Parsing belongs to the server; mock parsing belongs to lib/mock-filter.ts.
 * Read FilterBar for the error offset shown beside a literal copy of the input. */
import { lazy, Suspense, useState } from 'react'
import type { FilterError } from '../../api/types'
import { labels } from '../../lib/labels'
import { Button } from '../../components/ui/button'
import { Input } from '../../components/ui/input'
// The popover's focus-management code is only needed after the help button is used.
const FilterHelp = lazy(() => import('./FilterHelp'))
/** Applies on Enter or button press; an external conversation jump updates the draft. */
export function FilterBar({
  filter,
  error,
  apply,
}: {
  filter: string
  error: FilterError | null
  apply: (text: string) => void
}) {
  const [draft, setDraft] = useState(filter)
  const [helpLoaded, setHelpLoaded] = useState(false)
  const helpButton = (
    <Button type="button" variant="outline" onClick={() => setHelpLoaded(true)}>
      {labels.filterHelp}
    </Button>
  )
  return (
    <div className="filter-bar">
      <form
        onSubmit={(event) => {
          event.preventDefault()
          apply(draft)
        }}
      >
        <label className="sr-only" htmlFor="packet-filter">
          {labels.filter}
        </label>
        <Input
          id="packet-filter"
          value={draft}
          onChange={(event) => setDraft(event.target.value)}
          placeholder={labels.filter}
          aria-invalid={Boolean(error)}
          aria-describedby={error ? 'filter-error' : undefined}
        />
        <Button type="submit">{labels.apply}</Button>
        {helpLoaded ? (
          <Suspense fallback={helpButton}>
            <FilterHelp />
          </Suspense>
        ) : (
          helpButton
        )}
      </form>
      {error && (
        <div id="filter-error" role="alert" className="filter-error">
          <span>
            {labels.filterPosition} {error.position}: {error.message}
          </span>
          <pre>
            {draft}
            {'\n'}
            {' '.repeat(Math.min(4096, Math.max(0, error.position)))}^
          </pre>
        </div>
      )}
    </div>
  )
}
