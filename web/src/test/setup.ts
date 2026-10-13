/** Supplies deterministic browser geometry and cleanup for jsdom component tests.
 * Production browser behaviour stays in hooks and view components.
 * Read the ResizeObserver shim; tests exercise virtual rows without a real layout engine. */
import '@testing-library/jest-dom/vitest'
import { afterEach, beforeEach, vi } from 'vitest'
import { cleanup } from '@testing-library/react'

afterEach(() => {
  cleanup()
  history.replaceState(null, '', '/')
  sessionStorage.clear()
  vi.restoreAllMocks()
  vi.useRealTimers()
})
const matchMedia = (query: string) => ({
  matches: query.includes('min-width'),
  media: query,
  onchange: null,
  addListener() {},
  removeListener() {},
  addEventListener() {},
  removeEventListener() {},
  dispatchEvent() {
    return true
  },
})
Object.defineProperty(window, 'matchMedia', { writable: true, value: vi.fn(matchMedia) })
beforeEach(() => {
  vi.mocked(window.matchMedia).mockImplementation(matchMedia)
})
class TestResizeObserver {
  private readonly callback: ResizeObserverCallback
  constructor(callback: ResizeObserverCallback) {
    this.callback = callback
  }
  observe(target: Element) {
    this.callback(
      [
        {
          target,
          contentRect: target.getBoundingClientRect(),
          borderBoxSize: [{ inlineSize: 1000, blockSize: 360 }],
        } as unknown as ResizeObserverEntry,
      ],
      this as unknown as ResizeObserver,
    )
  }
  unobserve() {}
  disconnect() {}
}
vi.stubGlobal('ResizeObserver', TestResizeObserver)
Object.defineProperty(HTMLElement.prototype, 'getBoundingClientRect', {
  value() {
    // A full-window separator would make the resizer intercept every simulated pointer click.
    if (this.getAttribute('data-slot') === 'resizable-handle') {
      return {
        width: 1000,
        height: 1,
        top: 180,
        bottom: 181,
        left: 0,
        right: 1000,
        x: 0,
        y: 180,
        toJSON() {},
      }
    }
    return {
      width: 1000,
      height: 360,
      top: 0,
      left: 0,
      right: 1000,
      bottom: 360,
      x: 0,
      y: 0,
      toJSON() {},
    }
  },
})
Object.defineProperty(HTMLElement.prototype, 'clientHeight', {
  get() {
    return 360
  },
})
Object.defineProperty(HTMLElement.prototype, 'clientWidth', {
  get() {
    return 1000
  },
})
Object.defineProperty(HTMLElement.prototype, 'offsetHeight', {
  get() {
    return 360
  },
})
Object.defineProperty(HTMLElement.prototype, 'offsetWidth', {
  get() {
    return 1000
  },
})
HTMLElement.prototype.scrollTo = function (options?: ScrollToOptions | number, y?: number) {
  this.scrollTop = typeof options === 'object' ? (options.top ?? this.scrollTop) : (y ?? 0)
  this.dispatchEvent(new Event('scroll'))
}
HTMLElement.prototype.scrollIntoView = function () {}

// Virtualizer scroll targets clamp to scrollHeight; jsdom has no layout-generated scroll extent.
Object.defineProperty(HTMLElement.prototype, 'scrollHeight', {
  get() {
    const child = this.firstElementChild as HTMLElement | null
    return Math.max(360, Number.parseFloat(child?.style.height ?? '0') || 0)
  },
})
