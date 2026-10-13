/** Coordinates field selection with explanations and matching captured bytes.
 * Transport belongs to useDetail; byte lookup belongs to lib/hex.ts.
 * Read PacketDetailPane for the bidirectional teaching link and narrow-screen tabs. */
import { useState } from 'react'
import type { Field, GlossaryTerm, Layer, PacketDetail } from '../../api/types'
import { fieldAtByte, fieldPath, hiddenRanges } from '../../lib/hex'
import { labels } from '../../lib/labels'
import { useMediaQuery } from '../../hooks/useMediaQuery'
import { Button } from '../../components/ui/button'
import { Tabs, TabsContent, TabsList, TabsTrigger } from '../../components/ui/tabs'
import { LayersPane } from './LayersPane'
import { ExplainPane } from './ExplainPane'
import { BytesPane } from './BytesPane'

/** Remount on packet-number changes so selected fields always belong to this packet. */
export function PacketDetailPane({
  packet,
  terms,
  openFlow,
}: {
  packet: PacketDetail
  terms: GlossaryTerm[]
  openFlow: (id: number) => void
}) {
  const [selected, setSelected] = useState<Field | null>(null)
  const [selectedLayer, setSelectedLayer] = useState<Layer | null>(null)
  const [hovered, setHovered] = useState<Field | null>(null)
  const [expanded, setExpanded] = useState<Record<number, boolean>>({})
  const [openFields, setOpenFields] = useState<ReadonlySet<Field>>(new Set())
  const wide = useMediaQuery('(min-width: 1024px)')
  function choose(field: Field | null) {
    setSelected(field)
    setSelectedLayer(null)
    if (!field) return
    const path = fieldPath(packet.layers, field)
    setOpenFields((old) => new Set([...old, ...path]))
    const index = packet.layers.findIndex((layer) =>
      layer.fields.some((parent) => path.includes(parent)),
    )
    if (index >= 0) expand(index, true)
  }
  function expand(index: number, open: boolean) {
    setExpanded((old) => (old[index] === open ? old : { ...old, [index]: open }))
  }
  function toggleField(field: Field, open: boolean) {
    setOpenFields((old) => {
      if (old.has(field) === open) return old
      const next = new Set(old)
      if (open) next.add(field)
      else next.delete(field)
      return next
    })
  }
  const panes = {
    layers: (
      <LayersPane
        layers={packet.layers}
        selected={selected}
        select={choose}
        hover={setHovered}
        expanded={expanded}
        expand={expand}
        openFields={openFields}
        toggleField={toggleField}
        selectLayer={(layer) => {
          setSelected(null)
          setSelectedLayer(layer)
        }}
      />
    ),
    explain: <ExplainPane field={selected} layer={selectedLayer} packet={packet} terms={terms} />,
    bytes: (
      <BytesPane
        hidden={[...(packet.hidden ?? []), ...hiddenRanges(packet.layers)]}
        hex={packet.hex}
        range={(hovered ?? selected)?.range ?? null}
        choose={(offset) => {
          setHovered(null)
          choose(fieldAtByte(packet.layers, offset))
        }}
      />
    ),
  }
  function detailPanes() {
    if (wide)
      return (
        <div className="detail-columns">
          {panes.layers}
          {panes.explain}
          {panes.bytes}
        </div>
      )
    return (
      <Tabs className="detail-tabs" defaultValue="layers">
        <TabsList>
          {(['layers', 'explain', 'bytes'] as const).map((name) => (
            <TabsTrigger value={name} key={name}>
              {labels[name]}
            </TabsTrigger>
          ))}
        </TabsList>
        {(['layers', 'explain', 'bytes'] as const).map((name) => (
          <TabsContent className="detail-tab" key={name} value={name}>
            {panes[name]}
          </TabsContent>
        ))}
      </Tabs>
    )
  }
  return (
    <div className="packet-detail">
      <div className="detail-heading">
        <h2>
          {labels.openPacket} {packet.no}
        </h2>
        <span>
          {packet.captured_len} {labels.captured} / {packet.wire_len} {labels.wire}
        </span>
        {packet.truncated && <span className="problem-mark">⚠ {labels.truncated}</span>}
        {packet.flow !== null && (
          <Button
            variant="link"
            onClick={() => {
              if (packet.flow !== null) openFlow(packet.flow)
            }}
          >
            {labels.conversation} {packet.flow}
          </Button>
        )}
      </div>
      {detailPanes()}
    </div>
  )
}
