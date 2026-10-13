/** Searches literal glossary definitions while retaining a term selection in the route.
 * Inline term recognition belongs to lib/glossary.ts; navigation belongs to App.
 * Read GlossaryView; deep-linked terms are highlighted and scrolled into view. */
import { useEffect, useRef, useState } from 'react'
import type { GlossaryTerm } from '../../api/types'
import { labels } from '../../lib/labels'
import { moveListFocus } from '../../lib/navigation'
import { Input } from '../../components/ui/input'

/** Definitions remain exactly as received; selection is optional for standalone glossary rendering. */
export function GlossaryView({
  terms,
  selected = null,
  select,
}: {
  terms: GlossaryTerm[]
  selected?: string | null
  select?: (term: string) => void
}) {
  const [search, setSearch] = useState('')
  const list = useRef<HTMLDListElement>(null)
  const filtered = terms.filter((term) =>
    (term.term + ' ' + term.text).toLowerCase().includes(search.toLowerCase()),
  )
  useEffect(() => {
    list.current?.querySelector('[data-selected="true"]')?.scrollIntoView({ block: 'nearest' })
  }, [selected])
  return (
    <div className="glossary-view">
      <label htmlFor="glossary-search">{labels.glossarySearch}</label>
      <Input
        id="glossary-search"
        value={search}
        onChange={(event) => setSearch(event.target.value)}
      />
      <dl ref={list} onKeyDown={moveListFocus}>
        {filtered.map((term) => (
          <div
            key={term.term}
            tabIndex={0}
            data-list-item
            data-selected={term.term === selected}
            onClick={() => select?.(term.term)}
            onKeyDown={(event) => {
              if (event.key === 'Enter' || event.key === ' ') {
                event.preventDefault()
                select?.(term.term)
              }
            }}
          >
            <dt>{term.term}</dt>
            <dd>{term.text}</dd>
          </div>
        ))}
      </dl>
      {!filtered.length && <p className="empty-message">{labels.emptyGlossary}</p>}
    </div>
  )
}
