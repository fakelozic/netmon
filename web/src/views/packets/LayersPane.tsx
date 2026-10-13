/** Shows protocol headings with independently collapsible field trees.
 * Selected explanations belong to ExplainPane; parent coordination belongs to PacketDetailPane.
 * Read LayersPane; selecting a heading explains that protocol even while its fields are collapsed. */
import type { Field, Layer } from '../../api/types'
import { labels } from '../../lib/labels'
import { moveListFocus } from '../../lib/navigation'
import { FieldTree } from './FieldTree'

/** Only the highest protocol starts open; byte selection can reveal a lower layer. */
export function LayersPane({
  layers,
  selected,
  select,
  hover,
  expanded,
  expand,
  openFields,
  toggleField,
  selectLayer,
}: {
  layers: Layer[]
  selected: Field | null
  select: (field: Field) => void
  hover: (field: Field | null) => void
  expanded: Record<number, boolean>
  expand: (index: number, open: boolean) => void
  openFields: ReadonlySet<Field>
  toggleField: (field: Field, open: boolean) => void
  selectLayer: (layer: Layer) => void
}) {
  return (
    <section
      className="layers-pane pane-scroll"
      aria-label={labels.layers}
      onKeyDown={moveListFocus}
    >
      <h3>{labels.layers}</h3>
      {layers.map((layer, index) => (
        <details
          key={index}
          open={expanded[index] ?? index === layers.length - 1}
          onToggle={(event) => expand(index, event.currentTarget.open)}
        >
          <summary onClick={() => selectLayer(layer)}>
            <strong>{layer.proto}</strong>
            <span>{layer.line}</span>
          </summary>
          <FieldTree
            fields={layer.fields}
            selected={selected}
            select={select}
            hover={hover}
            expanded={openFields}
            toggle={toggleField}
          />
        </details>
      ))}
    </section>
  )
}
