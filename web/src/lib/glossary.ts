/** Splits text into literal text and whole glossary terms without making markup.
 * Rendering belongs to GlossaryText; definitions always come from the API.
 * Read splitGlossary for boundary and longest-term handling. */
import type { GlossaryTerm } from '../api/types'
/** A text span optionally associated with a complete definition. */
export interface GlossaryPart {
  text: string
  definition?: GlossaryTerm
}
/** Matches case-insensitively, longest terms first; punctuation is preserved exactly. */
export function splitGlossary(text: string, terms: GlossaryTerm[]): GlossaryPart[] {
  const sorted = terms
    .filter((t) => t.term.length > 0)
    .toSorted((a, b) => b.term.length - a.term.length)
  const escaped = sorted.map((t) => t.term.replace(/[.*+?^${}()|[\]\\]/g, '\\$&'))
  if (!escaped.length) return [{ text }]
  // ASCII identifiers include underscores; DNS inside DNSSEC is not the term DNS.
  const regex = new RegExp(`(?<![\\p{L}\\p{N}_])(${escaped.join('|')})(?![\\p{L}\\p{N}_])`, 'giu')
  const parts: GlossaryPart[] = []
  let cursor = 0
  for (const match of text.matchAll(regex)) {
    const index = match.index
    if (index > cursor) parts.push({ text: text.slice(cursor, index) })
    parts.push({
      text: match[0],
      definition: sorted.find((t) => t.term.toLowerCase() === match[0].toLowerCase()),
    })
    cursor = index + match[0].length
  }
  if (cursor < text.length) parts.push({ text: text.slice(cursor) })
  return parts
}
