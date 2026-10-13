/** Renders server sentences as literal React nodes with glossary tooltips.
 * Word matching belongs to lib/glossary.ts; definitions arrive from the API.
 * Read GlossaryText; no API string becomes markup, a URL or a class. */
import type { GlossaryTerm } from '../api/types'
import { splitGlossary } from '../lib/glossary'
import { Tooltip, TooltipContent, TooltipTrigger } from './ui/tooltip'
/** Adds keyboard-accessible definitions while preserving every character of the sentence. */
export function GlossaryText({ text, terms }: { text: string; terms: GlossaryTerm[] }) {
  return (
    <>
      {splitGlossary(text, terms).map((part, i) =>
        part.definition ? (
          <Tooltip key={i}>
            <TooltipTrigger asChild>
              <span tabIndex={0} className="glossary-word">
                {part.text}
              </span>
            </TooltipTrigger>
            <TooltipContent>{part.definition.text}</TooltipContent>
          </Tooltip>
        ) : (
          <span key={i}>{part.text}</span>
        ),
      )}
    </>
  )
}
