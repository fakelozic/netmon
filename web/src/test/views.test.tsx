/** Exercises fixture-based field learning, stories, glossary and alert views.
 * Hostile-text tests live in safety.test.tsx; transport tests live under api/.
 * Read the byte-highlight test for the main teaching interaction. */
import { fireEvent, render, screen, waitFor, within } from '@testing-library/react'
import { expect, it, vi } from 'vitest'
import App from '../App'
import { createMock } from '../api/mock'
import { fixtures } from '../api/mock-data'
import { labels } from '../lib/labels'
import { TooltipProvider } from '../components/ui/tooltip'
import { Story } from '../views/connections/Story'
import { AlertsView } from '../views/alerts/AlertsView'
import { GlossaryView } from '../views/glossary/GlossaryView'
import { SessionHeader } from '../components/SessionHeader'

it('renders packet rows; selecting a row and field shows its exact explanation and byte range', async () => {
  render(<App api={createMock(75)} mock />)
  await screen.findByRole('button', { name: 'Open packet 17' })
  fireEvent.click(screen.getByRole('button', { name: 'Open packet 17' }))
  await screen.findByRole('heading', { name: 'Open packet 17' })
  fireEvent.click(screen.getByText('IPv4', { selector: 'strong' }))
  fireEvent.click(screen.getByRole('button', { name: 'Time to live: 64' }))
  const explain = screen.getByRole('region', { name: labels.explain })
  expect(within(explain).getByRole('heading', { name: labels.what })).toBeInTheDocument()
  expect(within(explain).getByRole('heading', { name: labels.here })).toBeInTheDocument()
  expect(within(explain).getByRole('heading', { name: labels.why })).toBeInTheDocument()
  expect(explain.textContent).toContain('Stops packets circling forever.')
  const hex = screen.getByRole('button', { name: 'Hex Byte 22: 40' })
  expect(hex).toHaveAttribute('data-highlighted', 'true')
  expect(screen.getByRole('button', { name: 'ASCII Byte 22: @' })).toHaveAttribute(
    'data-highlighted',
    'true',
  )
  expect(screen.getByRole('button', { name: 'Hex Byte 23: 06' })).toHaveAttribute(
    'data-highlighted',
    'false',
  )
  fireEvent.mouseEnter(screen.getByRole('button', { name: 'Source port: 51008' }))
  expect(screen.getByRole('button', { name: 'Hex Byte 34: c7' })).toHaveAttribute(
    'data-highlighted',
    'true',
  )
  fireEvent.mouseLeave(screen.getByRole('button', { name: 'Source port: 51008' }))
  fireEvent.click(screen.getByRole('button', { name: 'Hex Byte 47: 02' }))
  expect(within(explain).getByRole('heading', { name: 'CWR' })).toBeInTheDocument()
})
it('submits a filter error without clearing the draft and displays its position', async () => {
  render(<App api={createMock(75)} />)
  const input = await screen.findByRole('textbox', { name: labels.filter })
  fireEvent.change(input, { target: { value: 'port wrong' } })
  fireEvent.click(screen.getByRole('button', { name: labels.apply }))
  await screen.findByText('Position 5: Expected a port number after "port".')
  expect(input).toHaveValue('port wrong')
  expect(document.querySelector('#filter-error pre')?.textContent).toBe('port wrong\n     ^')
})
it('renders every story step in observed order, with the right direction and packet jump', () => {
  const flow = fixtures.flows[6],
    jump = vi.fn()
  render(
    <TooltipProvider>
      <Story
        flow={flow}
        terms={[]}
        jump={jump}
        exportStory={vi.fn()}
        path={null}
        mock
        busy={false}
      />
    </TooltipProvider>,
  )
  const arrows = document.querySelectorAll<HTMLButtonElement>('.step-arrow')
  expect(arrows).toHaveLength(flow.story.length)
  expect([...arrows].map((arrow) => arrow.dataset.direction)).toEqual(
    flow.story.map((step) => step.dir),
  )
  expect([...document.querySelectorAll('.step-text')].map((node) => node.textContent)).toEqual(
    flow.story.map(
      (step) =>
        `${step.problem ? '⚠ ' : ''}${step.n}. ${step.text}Packets ${step.first_packet}–${step.last_packet}`,
    ),
  )
  fireEvent.click(arrows[1])
  expect(jump).toHaveBeenCalledWith(flow.story[1])
})
it('opens a conversation, exports its story and jumps to its first step packet', async () => {
  const api = createMock(75),
    control = vi.spyOn(api, 'control')
  render(<App api={api} mock />)
  fireEvent.click(await screen.findByRole('button', { name: 'Open packet 17' }))
  fireEvent.click(await screen.findByRole('button', { name: 'Open conversation 7' }))
  await screen.findByRole('region', { name: labels.story })
  fireEvent.click(screen.getByRole('button', { name: labels.export }))
  await screen.findByText(/Mock export path/)
  expect(control).toHaveBeenCalledWith({ action: 'export_story', flow: 7 })
  fireEvent.click(screen.getByRole('button', { name: 'Peer → initiator, Open packet 18' }))
  await screen.findByRole('heading', { name: 'Open packet 18' })
  expect(screen.getByText(/Conversation 7/)).toBeInTheDocument()
  await waitFor(() =>
    expect(screen.queryByRole('button', { name: 'Open packet 29' })).not.toBeInTheDocument(),
  )
})
it('shows each alert section verbatim and opens the triggering packet', () => {
  const alert = fixtures.alerts.alerts[0],
    jump = vi.fn()
  render(
    <TooltipProvider>
      <AlertsView alerts={[alert]} terms={[]} jump={jump} />
    </TooltipProvider>,
  )
  expect(screen.getByText(alert.seen)).toBeInTheDocument()
  expect(screen.getByText(alert.why)).toBeInTheDocument()
  expect(screen.getByText(alert.next)).toBeInTheDocument()
  fireEvent.click(screen.getByRole('button', { name: 'Open packet 20' }))
  expect(jump).toHaveBeenCalledWith(20)
})
it('filters glossary terms and supports keyboard movement among definitions', () => {
  render(<GlossaryView terms={fixtures.glossary.terms} />)
  fireEvent.change(screen.getByRole('textbox'), { target: { value: 'window scale' } })
  expect(screen.getByText('window scale')).toBeInTheDocument()
  expect(screen.queryByText('ARP')).not.toBeInTheDocument()
  const item = document.querySelector<HTMLElement>('[data-list-item]')!
  item.focus()
  fireEvent.keyDown(item, { key: 'Home' })
  expect(item).toHaveFocus()
  fireEvent.change(screen.getByRole('textbox'), { target: { value: 'missingzz' } })
  expect(screen.getByText(labels.emptyGlossary)).toBeInTheDocument()
})
it('omits a rate chart in file mode and shows capture/logging failures', () => {
  render(
    <SessionHeader
      session={{
        ...fixtures.session,
        mode: 'file',
        state: 'failed',
        error: 'Capture reader failed.',
        problem: 'Log folder unavailable.',
      }}
      mock={false}
      dark={false}
      toggleTheme={vi.fn()}
      busy={false}
      control={vi.fn()}
    />,
  )
  expect(screen.queryByRole('img', { name: labels.rate })).not.toBeInTheDocument()
  expect(screen.getByText('Capture reader failed.')).toBeInTheDocument()
  expect(screen.getByText('Warning: Log folder unavailable.')).toBeInTheDocument()
})
it('shows glossary tooltips and toggles the theme by keyboard-accessible buttons', async () => {
  render(<App api={createMock(75)} />)
  fireEvent.click(await screen.findByRole('button', { name: labels.dark }))
  expect(document.documentElement).toHaveClass('dark')
  fireEvent.click(screen.getByRole('button', { name: labels.light }))
  expect(document.documentElement).not.toHaveClass('dark')
  fireEvent.click(screen.getByRole('button', { name: 'Open packet 17' }))
  await screen.findByRole('heading', { name: 'Open packet 17' })
  const term = document.querySelector<HTMLElement>('.explain-pane .layer-about .glossary-word')!
  fireEvent.focus(term)
  await screen.findByRole('tooltip')
  expect(screen.getByRole('tooltip').textContent).toContain(
    fixtures.glossary.terms.find((t) => t.term.toLowerCase() === term.textContent!.toLowerCase())!
      .text,
  )
})

it('loads filter help on demand and restores keyboard focus after Escape', async () => {
  render(<App api={createMock(75)} />)
  const trigger = await screen.findByRole('button', { name: labels.filterHelp })
  expect(screen.queryByText('(dns or tls)')).not.toBeInTheDocument()
  fireEvent.click(trigger)
  await screen.findByText('(dns or tls)')
  fireEvent.keyDown(document.activeElement!, { key: 'Escape' })
  await waitFor(() => expect(screen.queryByText('(dns or tls)')).not.toBeInTheDocument())
  expect(screen.getByRole('button', { name: labels.filterHelp })).toHaveFocus()
})
