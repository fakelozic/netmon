/** Renders a decoded field tree with literal values and a byte-range preview.
 * Byte lookup belongs to lib/hex.ts; explanation wording comes from the server.
 * Read FieldTree; child fields can overlap their parent's byte range. */
import type { Field } from '../../api/types'
/** Recursive fields retain header order; selected descendants keep their parents open. */
export function FieldTree({
  fields,
  selected,
  select,
  hover,
  expanded,
  toggle,
}: {
  fields: Field[]
  selected: Field | null
  select: (field: Field) => void
  hover: (field: Field | null) => void
  expanded: ReadonlySet<Field>
  toggle: (field: Field, open: boolean) => void
}) {
  return (
    <ul className="field-tree">
      {fields.map((field, index) => (
        <li key={index}>
          {field.children.length > 0 ? (
            <details
              open={expanded.has(field)}
              onToggle={(event) => toggle(field, event.currentTarget.open)}
            >
              <summary>
                <button
                  className={field === selected ? 'selected-field' : ''}
                  onClick={() => select(field)}
                  onMouseEnter={() => hover(field)}
                  onMouseLeave={() => hover(null)}
                >
                  {field.label}: <span>{field.value}</span>
                </button>
              </summary>
              <FieldTree
                fields={field.children}
                selected={selected}
                select={select}
                hover={hover}
                expanded={expanded}
                toggle={toggle}
              />
            </details>
          ) : (
            <button
              className={field === selected ? 'selected-field' : ''}
              onClick={() => select(field)}
              onMouseEnter={() => hover(field)}
              onMouseLeave={() => hover(null)}
            >
              {field.label}: <span>{field.value}</span>
            </button>
          )}
        </li>
      ))}
    </ul>
  )
}
