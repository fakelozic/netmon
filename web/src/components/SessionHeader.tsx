/** Shows capture status in one compact row with counters and controls.
 * API actions belong to useMonitor; packet views own selection.
 * Read SessionHeader; rate samples are bytes per second, not packet counts. */
import { Circle, Moon, Pause, Play, Sun } from 'lucide-react'
import type { ControlAction, Session } from '../api/types'
import { labels } from '../lib/labels'
import { formatBytes } from '../lib/format'
import { Button } from './ui/button'
import { Badge } from './ui/badge'
import { Alert, AlertDescription } from './ui/alert'

const states = {
  running: labels.live,
  paused: labels.paused,
  ended: labels.ended,
  failed: labels.failed,
}

/** Alerts sit outside the 56-pixel header so errors cannot hide the capture controls. */
export function SessionHeader({
  session,
  mock,
  dark,
  toggleTheme,
  busy,
  control,
}: {
  session: Session
  mock: boolean
  dark: boolean
  toggleTheme: () => void
  busy: boolean
  control: (action: ControlAction) => void
}) {
  const rate = session.rate.slice(-60)
  const max = Math.max(1, ...rate)
  const points = rate
    .map(
      (value, i) =>
        `${(i * 64) / Math.max(1, rate.length - 1)},${24 - (Math.max(0, value) * 22) / max}`,
    )
    .join(' ')
  return (
    <>
      <header className="session-header">
        <h1>netmon</h1>
        <Badge variant={session.state === 'failed' ? 'destructive' : 'secondary'}>
          {states[session.state]}
        </Badge>
        <span className="source" title={mock ? labels.mockSource : session.source}>
          {mock && <>{labels.mock} · </>}
          {session.mode === 'file' && <>{labels.file} · </>}
          {session.source}
        </span>
        <div className="metrics">
          <span>
            <strong>{session.packets.toLocaleString()}</strong> {labels.packets}
          </span>
          <span>
            <strong>{session.conversations}</strong> {labels.connections}
          </span>
          <span>
            <strong>{session.alerts}</strong> {labels.alerts}
          </span>
          <span className="extra-metric">{formatBytes(session.bytes)}</span>
          <span className="extra-metric">
            {labels.dropped}: {session.dropped}
          </span>
        </div>
        {session.mode === 'live' && (
          <div className="rate">
            <svg viewBox="0 0 64 26" role="img" aria-label={labels.rate}>
              <polyline fill="none" stroke="currentColor" strokeWidth="2" points={points} />
            </svg>
            <span>{formatBytes(rate.at(-1) ?? 0)}/s</span>
          </div>
        )}
        <div className="header-actions">
          <Button
            variant="outline"
            disabled={busy || ['ended', 'failed'].includes(session.state)}
            onClick={() => control({ action: session.state === 'paused' ? 'resume' : 'pause' })}
          >
            {session.state === 'paused' ? <Play /> : <Pause />}
            {session.state === 'paused' ? labels.resume : labels.pause}
          </Button>
          <Button
            variant={session.recording === 'on' ? 'destructive' : 'outline'}
            title={session.recording}
            aria-pressed={session.recording === 'on'}
            disabled={
              busy || session.mode === 'file' || ['ended', 'failed'].includes(session.state)
            }
            onClick={() =>
              control({ action: session.recording === 'on' ? 'record_stop' : 'record_start' })
            }
          >
            <Circle />
            {session.recording === 'on' ? labels.stopRecord : labels.record}
          </Button>
          <Button
            variant="ghost"
            size="icon"
            aria-label={dark ? labels.light : labels.dark}
            onClick={toggleTheme}
          >
            {dark ? <Sun /> : <Moon />}
          </Button>
        </div>
      </header>
      {session.error && (
        <Alert variant="destructive">
          <AlertDescription>{session.error}</AlertDescription>
        </Alert>
      )}
      {session.problem && (
        <Alert>
          <AlertDescription>
            {labels.warning}: {session.problem}
          </AlertDescription>
        </Alert>
      )}
    </>
  )
}
