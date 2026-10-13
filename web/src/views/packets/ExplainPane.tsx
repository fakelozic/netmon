/** Shows the selected field or protocol, with packet context as the initial explanation.
 * Selection belongs to PacketDetailPane; all networking sentences come from the server.
 * Read ExplainPane; empty field sections are omitted without leaving the initial pane empty. */
import type { Field, GlossaryTerm, Layer, PacketDetail } from '../../api/types'
import { labels } from '../../lib/labels'
import { GlossaryText } from '../../components/GlossaryText'

/** With no field or heading selected, shows the packet sentence and highest layer's about text. */
export function ExplainPane({
  field,
  layer,
  packet,
  terms,
}: {
  field: Field | null
  layer: Layer | null
  packet: PacketDetail
  terms: GlossaryTerm[]
}) {
  const about = layer ?? packet.layers.at(-1)
  function explanation() {
    if (field)
      return (
        <>
          <h4>{field.label}</h4>
          <code>{field.value}</code>
          {(['what', 'here', 'why'] as const).map(
            (part) =>
              field[part] && (
                <div key={part}>
                  <h5>{labels[part]}</h5>
                  <p>
                    <GlossaryText text={field[part]} terms={terms} />
                  </p>
                </div>
              ),
          )}
        </>
      )
    return (
      <>
        {!layer && (
          <p className="packet-sentence">
            <GlossaryText text={packet.info} terms={terms} />
          </p>
        )}
        {about && (
          <>
            <h4>{about.proto}</h4>
            <p className="layer-about">
              <GlossaryText text={about.about} terms={terms} />
            </p>
          </>
        )}
        <p className="field-hint">{labels.fieldHint}</p>
      </>
    )
  }
  return (
    <section className="explain-pane pane-scroll" aria-label={labels.explain}>
      <h3>{labels.explain}</h3>
      {explanation()}
    </section>
  )
}
