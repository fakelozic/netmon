/** Verifies pane structure and teaching interactions without claiming browser geometry.
 * CSS fit and drag behaviour require browser review; deterministic selection runs in jsdom.
 * Read the byte-scroll test for selecting a field beyond the initial virtual viewport. */
import { fireEvent, render, screen, within } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { expect, it, vi } from 'vitest'
import { fixtures } from '../api/mock-data'
import { labels } from '../lib/labels'
import { PacketTable } from '../views/packets/PacketTable'
import { PacketDetailPane } from '../views/packets/PacketDetailPane'
import { TooltipProvider } from '../components/ui/tooltip'

// Virtualised tables expose only nearby rows; these five pages cover every fixture sentence.
it.each([0, 15, 30, 45, 60])(
  'keeps each sentence in its table cell on page starting at %i',
  (start) => {
    const rows = fixtures.packets.rows.slice(start, start + 15)
    render(
      <PacketTable
        rows={rows}
        selected={null}
        select={vi.fn()}
        follow={false}
        following={false}
        stopFollowing={vi.fn()}
      />,
    )
    const table = screen.getByRole('table')
    expect(
      within(table)
        .getAllByRole('columnheader')
        .map((header) => header.textContent),
    ).toEqual(['No', 'Time', 'From', 'To', 'App', 'Proto', 'What is happening', 'Bytes'])
    for (const row of rows) {
      const element = within(table)
        .getByRole('button', { name: 'Open packet ' + row.no })
        .closest('[role=row]')!
      const cell = within(element as HTMLElement).getByRole('cell', { name: row.info })
      expect(cell).toHaveAttribute('title', row.info)
      expect(within(cell.parentElement!).getAllByRole('cell')[6]).toBe(cell)
    }
  },
)

it('starts with the highest layer open and a nonempty Explain pane; headings explain their layer', () => {
  const packet = fixtures.details[16]
  const { container } = render(
    <TooltipProvider>
      <PacketDetailPane packet={packet} terms={[]} openFlow={vi.fn()} />
    </TooltipProvider>,
  )
  const layers = container.querySelectorAll<HTMLDetailsElement>('.layers-pane > details')
  expect([...layers].map((layer) => layer.open)).toEqual(
    packet.layers.map((_, i) => i === packet.layers.length - 1),
  )
  const explain = screen.getByRole('region', { name: labels.explain })
  expect(within(explain).getByText(packet.info)).toBeInTheDocument()
  expect(within(explain).getByText(packet.layers.at(-1)!.about)).toBeInTheDocument()
  fireEvent.click(screen.getByText('IPv4', { selector: 'strong' }))
  expect(
    within(explain).getByText(packet.layers.find((layer) => layer.proto === 'IPv4')!.about),
  ).toBeInTheDocument()
  expect(screen.getByRole('region', { name: labels.layers })).toHaveClass('pane-scroll')
  expect(explain).toHaveClass('pane-scroll')
  expect(screen.getByRole('region', { name: labels.bytes })).toBeInTheDocument()
})

it('switches detail panes to accessible tabs below 1024 pixels', async () => {
  vi.spyOn(window, 'matchMedia').mockImplementation((query) => ({
    matches: false,
    media: query,
    onchange: null,
    addListener() {},
    removeListener() {},
    addEventListener() {},
    removeEventListener() {},
    dispatchEvent() {
      return true
    },
  }))
  render(
    <TooltipProvider>
      <PacketDetailPane packet={fixtures.details[16]} terms={[]} openFlow={vi.fn()} />
    </TooltipProvider>,
  )
  expect(screen.getByRole('tab', { name: labels.layers })).toHaveAttribute('aria-selected', 'true')
  await userEvent.click(screen.getByRole('tab', { name: labels.explain }))
  expect(screen.getByRole('region', { name: labels.explain })).toHaveTextContent(
    fixtures.details[16].info,
  )
  await userEvent.click(screen.getByRole('tab', { name: labels.bytes }))
  expect(screen.getByRole('button', { name: 'Hex Byte 0: 00' })).toBeInTheDocument()
})

it('scrolls a selected offscreen field into the byte view and highlights hex and ASCII', () => {
  const packet = fixtures.details[16]
  const field = {
    ...packet.layers[0].fields[0],
    label: 'Far field',
    range: [800, 803] as [number, number],
  }
  const { container } = render(
    <TooltipProvider>
      <PacketDetailPane
        packet={{
          ...packet,
          hex: '41'.repeat(1024),
          layers: [{ ...packet.layers[0], fields: [field] }],
        }}
        terms={[]}
        openFlow={vi.fn()}
      />
    </TooltipProvider>,
  )
  expect(screen.queryByRole('button', { name: 'Hex Byte 800: 41' })).not.toBeInTheDocument()
  fireEvent.click(screen.getByRole('button', { name: 'Far field: ' + field.value }))
  expect(container.querySelector('.hex-scroll')!.scrollTop).toBeGreaterThan(0)
  expect(screen.getByRole('button', { name: 'Hex Byte 800: 41' })).toHaveAttribute(
    'data-highlighted',
    'true',
  )
  expect(screen.getByRole('button', { name: 'ASCII Byte 800: A' })).toHaveAttribute(
    'data-highlighted',
    'true',
  )
})
