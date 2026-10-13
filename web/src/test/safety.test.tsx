/** Verifies hostile API strings remain visible text across the main surfaces.
 * Contract sanitation belongs to the server; React children are the page's safety boundary.
 * Read the parameterised payload tests; no network or HTML parser is invoked by the page. */
import { render, screen } from '@testing-library/react'
import { expect, it, vi } from 'vitest'
import { labels } from '../lib/labels'
import { fixtures } from '../api/mock-data'
import { PacketTable } from '../views/packets/PacketTable'
import { PacketDetailPane } from '../views/packets/PacketDetailPane'
import { Story } from '../views/connections/Story'
import { AlertsView } from '../views/alerts/AlertsView'
import { GlossaryText } from '../components/GlossaryText'
import { TooltipProvider } from '../components/ui/tooltip'

it.each(['<img src=x onerror=1>', '"><script>alert(1)</script>', 'x'.repeat(12000)])(
  'renders hostile row, field, server name and alert title literally (%#)',
  (payload) => {
    const detail = fixtures.details[16]
    const firstLayer = detail.layers[0]
    const hostile = {
      ...detail,
      layers: [{ ...firstLayer, fields: [{ ...firstLayer.fields[0], value: payload }] }],
    }
    const { container } = render(
      <TooltipProvider>
        <PacketTable
          rows={[{ ...fixtures.packets.rows[0], info: payload, src_label: payload }]}
          selected={1}
          select={vi.fn()}
          follow={false}
          following={false}
          stopFollowing={vi.fn()}
        />
        <PacketDetailPane packet={hostile} terms={[]} openFlow={vi.fn()} />
        <Story
          flow={{ ...fixtures.flows[0], title: payload, remote_name: payload }}
          terms={[]}
          jump={vi.fn()}
          exportStory={vi.fn()}
          path={null}
          mock
          busy={false}
        />
        <AlertsView
          alerts={[{ ...fixtures.alerts.alerts[0], title: payload }]}
          terms={[]}
          jump={vi.fn()}
        />
        <GlossaryText text={payload + ' TCP'} terms={fixtures.glossary.terms} />
      </TooltipProvider>,
    )
    expect(screen.getAllByText(payload).length).toBeGreaterThanOrEqual(5)
    expect(container.querySelectorAll('img, script')).toHaveLength(0)
    expect(document.querySelectorAll('img, script')).toHaveLength(0)
  },
)
it('masks secret bytes in hex, ASCII and accessible labels when a field is hidden', () => {
  const detail = fixtures.details[16]
  const bytes = new TextEncoder().encode('secret')
  const packet = {
    ...detail,
    hex: [...bytes].map((b) => b.toString(16)).join(''),
    layers: [
      {
        ...detail.layers[0],
        fields: [
          {
            ...detail.layers[0].fields[0],
            label: 'Authorization',
            value: 'Basic [hidden]',
            range: [0, 6] as [number, number],
          },
        ],
      },
    ],
  }
  const { container } = render(
    <TooltipProvider>
      <PacketDetailPane packet={packet} terms={[]} openFlow={vi.fn()} />
    </TooltipProvider>,
  )
  expect(container.textContent).not.toContain('secret')
  expect(screen.getByRole('button', { name: 'Hex Byte 0: **' })).toBeInTheDocument()
  expect(screen.getByRole('button', { name: 'ASCII Byte 0: *' })).toBeInTheDocument()
  expect(screen.queryByRole('button', { name: 'Hex Byte 0: 73' })).not.toBeInTheDocument()
})

it('masks explicit hidden ranges even when no field is marked hidden, including boundary bytes', () => {
  const packet = {
    ...fixtures.details[16],
    hex: '414200004344',
    hidden: [[2, 4] as [number, number]],
  }
  render(
    <TooltipProvider>
      <PacketDetailPane packet={packet} terms={[]} openFlow={vi.fn()} />
    </TooltipProvider>,
  )
  for (const offset of [2, 3]) {
    expect(screen.getByRole('button', { name: `Hex Byte ${offset}: **` })).toHaveAttribute(
      'title',
      labels.hiddenSecret,
    )
    expect(screen.getByRole('button', { name: `ASCII Byte ${offset}: *` })).toHaveAttribute(
      'title',
      labels.hiddenSecret,
    )
    expect(screen.queryByRole('button', { name: `Hex Byte ${offset}: 00` })).not.toBeInTheDocument()
  }
  expect(screen.getByRole('button', { name: 'Hex Byte 1: 42' })).toBeInTheDocument()
  expect(screen.getByRole('button', { name: 'Hex Byte 4: 43' })).toBeInTheDocument()
})
