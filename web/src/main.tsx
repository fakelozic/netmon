/** Creates one API instance before React starts and consumes the URL token once.
 * View state belongs to App; real requests and fixture replay belong to api/.
 * Read the mock selection before changing how a session opens. */
import { StrictMode } from 'react'
import { createRoot } from 'react-dom/client'
import { readToken } from './api/client'
import { createPageApi } from './api/bootstrap'
import { labels } from './lib/labels'
import './index.css'
import App from './App'

const token = readToken()
// Constructing transport before render keeps StrictMode from consuming the token twice.
const { api, mock } = await createPageApi(
  token,
  window.location.search,
  import.meta.env.VITE_MOCK === '1',
)
const root = document.getElementById('root')
if (root)
  createRoot(root).render(
    <StrictMode>
      {api ? (
        <App api={api} mock={mock} />
      ) : (
        <main className="empty-message">
          <p role="status">{labels.mockUnavailable}</p>
        </main>
      )}
    </StrictMode>,
  )
