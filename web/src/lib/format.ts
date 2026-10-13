/** Formats contract units for the page without changing server sentences.
 * Packet byte layout belongs to hex.ts; labels belong to labels.ts.
 * Start with formatTime for packet-relative seconds. */
import { labels } from './labels'
/** Seconds since capture start, truncated to six decimal places. */
export function formatTime(seconds: number): string {
  const micros = Math.floor(Math.abs(seconds) * 1e6 + 1e-7)
  return `${seconds < 0 ? '-' : ''}${Math.floor(micros / 1e6)}.${String(micros % 1e6).padStart(6, '0')}`
}
/** Decimal byte units, preserving small integer counts. */
export function formatBytes(bytes: number): string {
  const units = ['B', 'kB', 'MB', 'GB']
  let unit = 0
  while (Math.abs(bytes) >= 1000 && unit < units.length - 1) {
    bytes /= 1000
    unit++
  }
  return `${unit ? bytes.toFixed(1) : bytes} ${units[unit]}`
}
/** Milliseconds from the API; null denotes an ongoing conversation. */
export function formatDuration(ms: number | null): string {
  if (ms === null) return labels.ongoing
  if (ms === 0) return '0 ms'
  if (Math.abs(ms) < 1) return `${Number((ms * 1000).toFixed(1))} µs`
  if (Math.abs(ms) < 1000) return `${Number(ms.toFixed(1))} ms`
  return `${Number((ms / 1000).toFixed(2))} s`
}
