/** Checks the entry point's message when production cannot provide mock mode.
 * Replay selection belongs to api/bootstrap.ts; normal views have their own component tests.
 * Read the fetch assertion: an unavailable replay must not poll a real session. */
import type { ReactNode } from 'react'
import { render, screen } from '@testing-library/react'
import { afterEach, expect, it, vi } from 'vitest'
import { labels } from '../lib/labels'

// Register the entry point's root with Testing Library so cleanup also unmounts it.
vi.mock('react-dom/client', () => ({
  createRoot: (container: HTMLElement) => ({
    render: (node: ReactNode) => render(node, { container }),
  }),
}))

afterEach(() => vi.unstubAllEnvs())

it('shows the unavailable message for production ?mock even with VITE_MOCK=1', async () => {
  vi.stubEnv('NETMON_INCLUDE_MOCK', '0')
  vi.stubEnv('DEV', false)
  vi.stubEnv('MODE', 'production')
  vi.stubEnv('VITE_MOCK', '1')
  history.replaceState(null, '', '/?mock=all')
  const root = document.createElement('div')
  root.id = 'root'
  document.body.append(root)
  const fetcher = vi.spyOn(globalThis, 'fetch')

  await import('../main')

  expect(screen.getByRole('status')).toHaveTextContent(labels.mockUnavailable)
  expect(screen.queryByRole('tablist')).not.toBeInTheDocument()
  expect(fetcher).not.toHaveBeenCalled()
})
