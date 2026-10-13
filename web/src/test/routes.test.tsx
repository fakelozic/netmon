/** Exercises route state through the actual App and browser history events.
 * Parsing edge cases live in lib/routes.test.ts; transport tests cover token consumption.
 * Read the Back/Forward test for two-way selection and filter restoration. */
import { fireEvent, render, screen, waitFor } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { expect, it, vi } from 'vitest'
import App from '../App'
import { createMock } from '../api/mock'
import { labels } from '../lib/labels'

it.each([
  ['#/packets', 'Packets', null],
  ['#/packets/17', 'Packets', 'Open packet 17'],
  ['#/connections', 'Connections', null],
  ['#/connections/7', 'Connections', 'Open conversation 7'],
  ['#/alerts', 'Alerts', null],
  ['#/glossary', 'Glossary', null],
  ['#/glossary/window%20scale', 'Glossary', 'window scale'],
] as const)('opens %s with the right tab and selection', async (hash, tab, selection) => {
  history.replaceState(null, '', hash)
  const api = createMock(75)
  const packet = vi.spyOn(api, 'packet'),
    flow = vi.spyOn(api, 'flow')
  render(<App api={api} />)
  expect(await screen.findByRole('tab', { name: new RegExp('^' + tab) })).toHaveAttribute(
    'aria-selected',
    'true',
  )
  if (selection === 'Open packet 17') {
    await screen.findByRole('heading', { name: selection })
    expect(packet).toHaveBeenCalledWith(17, expect.any(AbortSignal))
  }
  if (selection === 'Open conversation 7') {
    await screen.findByRole('region', { name: labels.story })
    expect(flow).toHaveBeenCalledWith(7, expect.any(AbortSignal))
  }
  if (selection === 'window scale') {
    expect(screen.getByText(selection).closest('[data-list-item]')).toHaveAttribute(
      'data-selected',
      'true',
    )
  }
  expect(location.hash).toBe(hash)
})

it('updates routes on tab, packet, connection and glossary selection', async () => {
  render(<App api={createMock(75)} />)
  fireEvent.click(await screen.findByRole('button', { name: 'Open packet 17' }))
  expect(location.hash).toBe('#/packets/17')
  fireEvent.click(await screen.findByRole('button', { name: 'Open conversation 7' }))
  expect(location.hash).toBe('#/connections/7')
  await screen.findByRole('region', { name: labels.story })
  await userEvent.click(screen.getByRole('tab', { name: labels.glossary }))
  expect(location.hash).toBe('#/glossary')
  fireEvent.click(screen.getByText('ACK', { selector: 'dt' }))
  expect(location.hash).toBe('#/glossary/ACK')
})

it('restores the previous selection with Back, then Forward restores the tab', async () => {
  history.replaceState(null, '', '#/packets/17?filter=tcp')
  render(<App api={createMock(75)} />)
  await screen.findByRole('heading', { name: 'Open packet 17' })
  await userEvent.click(screen.getByRole('tab', { name: labels.connections }))
  expect(location.hash).toBe('#/connections')
  history.back()
  await waitFor(() => expect(location.hash).toBe('#/packets/17?filter=tcp'))
  await screen.findByRole('heading', { name: 'Open packet 17' })
  expect(screen.getByRole('textbox', { name: labels.filter })).toHaveValue('tcp')
  history.forward()
  await waitFor(() =>
    expect(screen.getByRole('tab', { name: labels.connections })).toHaveAttribute(
      'aria-selected',
      'true',
    ),
  )
  expect(location.hash).toBe('#/connections')
})

it('reads external hash changes, applies deep-linked filters and normalises unknown routes', async () => {
  history.replaceState(null, '', '#/packets?filter=dns')
  render(<App api={createMock(75)} />)
  const input = await screen.findByRole('textbox', { name: labels.filter })
  expect(input).toHaveValue('dns')
  expect(screen.getAllByRole('cell', { name: 'DNS' })).toHaveLength(8)
  fireEvent.change(input, { target: { value: 'tls' } })
  fireEvent.click(screen.getByRole('button', { name: labels.apply }))
  expect(location.hash).toBe('#/packets?filter=tls')
  location.hash = '#/alerts'
  await waitFor(() =>
    expect(screen.getByRole('tab', { name: /Alerts/ })).toHaveAttribute('aria-selected', 'true'),
  )
  location.hash = '#/unknown/99'
  await waitFor(() => expect(location.hash).toBe('#/packets'))
  expect(screen.getByRole('tab', { name: labels.packets })).toHaveAttribute('aria-selected', 'true')
})
