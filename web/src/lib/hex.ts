/** Maps captured bytes to decoded fields using half-open packet offsets.
 * Field explanations belong to the API; interactive rendering belongs to BytesPane.
 * Read fieldAtByte for the teaching link from a byte back to its field. */
import type { ByteRange, Field, Layer } from '../api/types'
/** One sixteen-byte row; byte offsets remain absolute within the packet. */
export interface HexRow {
  offset: number
  bytes: { offset: number; hex: string; ascii: string }[]
}
/** True only for bytes inside [start, end), including empty and truncated ranges. */
export function inRange(offset: number, range: ByteRange | null): boolean {
  return range !== null && offset >= range[0] && offset < range[1]
}
/** Returns covered captured offsets; ranges beyond the captured length are clipped. */
export function coveredBytes(range: ByteRange, length: number): number[] {
  const start = Math.max(0, Math.min(length, Math.ceil(range[0])))
  const end = Math.max(start, Math.min(length, Math.ceil(range[1])))
  return Array.from({ length: end - start }, (_, i) => start + i)
}
/** Hex input is capped at the contract's 65,536 captured bytes; invalid pairs display nothing. */
export function hexRows(hex: string, hidden: ByteRange[] = []): HexRow[] {
  const pairs = hex.slice(0, 131072).match(/[0-9a-f]{2}/gi) ?? []
  const rows: HexRow[] = []
  for (let i = 0; i < pairs.length; i += 16) {
    rows.push({
      offset: i,
      bytes: pairs.slice(i, i + 16).map((pair, j) => {
        const byte = parseInt(pair, 16)
        const masked = hidden.some((range) => inRange(i + j, range))
        return {
          offset: i + j,
          hex: masked ? '**' : pair,
          ascii: masked ? '*' : byte >= 32 && byte <= 126 ? String.fromCharCode(byte) : '.',
        }
      }),
    })
  }
  return rows
}
/** Chooses greatest tree depth; equal-depth overlaps choose the first field in header order. */
export function fieldAtByte(layers: Layer[], offset: number): Field | null {
  let found: Field | null = null
  let deepest = -1
  function visit(fields: Field[], depth: number) {
    for (const field of fields) {
      if (inRange(offset, field.range) && depth > deepest) {
        found = field
        deepest = depth
      }
      visit(field.children, depth + 1)
    }
  }
  layers.forEach((layer) => visit(layer.fields, 0))
  return found
}

/** Masks every range marked [hidden] by the server, including nested header fields. */
export function hiddenRanges(layers: Layer[]): ByteRange[] {
  const ranges: ByteRange[] = []
  function visit(fields: Field[]) {
    for (const field of fields) {
      // Retain masking for replies that only mark fields. Explicit ranges also cover secrets without fields.
      if (field.value.includes('[hidden]')) ranges.push(field.range)
      visit(field.children)
    }
  }
  layers.forEach((layer) => visit(layer.fields))
  return ranges
}

/** Returns the selected field's ancestor path, including the field itself; an absent field yields []. */
export function fieldPath(layers: Layer[], target: Field): Field[] {
  function find(fields: Field[], path: Field[]): Field[] | null {
    for (const field of fields) {
      const next = [...path, field]
      if (field === target) return next
      const found = find(field.children, next)
      if (found) return found
    }
    return null
  }
  for (const layer of layers) {
    const path = find(layer.fields, [])
    if (path) return path
  }
  return []
}
