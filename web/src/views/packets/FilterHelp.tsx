/** Loads the filter-language help popover when a reader asks for it.
 * Filter submission belongs to FilterBar; networking explanations arrive through the API.
 * Read FilterHelp; shadcn retains popup focus handling and Escape behaviour. */
import { labels } from '../../lib/labels'
import { Button } from '../../components/ui/button'
import { Popover, PopoverContent, PopoverTrigger } from '../../components/ui/popover'

/** Opens on first load, then retains its trigger for normal keyboard focus restoration. */
export default function FilterHelp() {
  return (
    <Popover defaultOpen>
      <PopoverTrigger asChild>
        <Button type="button" variant="outline">
          {labels.filterHelp}
        </Button>
      </PopoverTrigger>
      <PopoverContent>
        <strong>{labels.filterHelp}</strong>
        <div className="filter-words">
          {labels.filterWords.map((word) => (
            <code key={word}>{word}</code>
          ))}
        </div>
      </PopoverContent>
    </Popover>
  )
}
