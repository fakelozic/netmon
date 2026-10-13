/** Coordinates the four views around one capture snapshot and fragment route.
 * API construction belongs to main.tsx; transport and polling stay outside components.
 * Read App for packet, story and alert navigation through browser history. */
import { useEffect, useState } from 'react'
import type { Flow, FlowSort, NetmonApi, StoryStep } from './api/types'
import { useMonitor } from './hooks/useMonitor'
import { useRoute } from './hooks/useRoute'
import { packetRoute, type PageRoute } from './lib/routes'
import { labels } from './lib/labels'
import { SessionHeader } from './components/SessionHeader'
import { Button } from './components/ui/button'
import { Skeleton } from './components/ui/skeleton'
import { Alert, AlertDescription } from './components/ui/alert'
import { Tabs, TabsContent, TabsList, TabsTrigger } from './components/ui/tabs'
import { TooltipProvider } from './components/ui/tooltip'
import { PacketsView } from './views/packets/PacketsView'
import { ConnectionsView } from './views/connections/ConnectionsView'
import { AlertsView } from './views/alerts/AlertsView'
import { GlossaryView } from './views/glossary/GlossaryView'
import './App.css'

/** Uses a provided real or mock API; network text is passed only to React children. */
export default function App({ api, mock = false }: { api: NetmonApi; mock?: boolean }) {
  const { route, navigate } = useRoute()
  const [sort, setSort] = useState<FlowSort>('recent')
  const [dark, setDark] = useState(() => window.matchMedia('(prefers-color-scheme: dark)').matches)
  const monitor = useMonitor(api, route.filter, sort, null, route.packet)
  const rows =
    route.scope === null ? monitor.rows : monitor.rows.filter((row) => row.flow === route.scope)
  const selectedPacket = route.packet ?? rows[0]?.no ?? null
  useEffect(() => {
    document.documentElement.classList.toggle('dark', dark)
  }, [dark])
  function changeTab(tab: string) {
    navigate({ ...route, tab: tab as PageRoute['tab'] })
  }
  function apply(filter: string) {
    navigate({ ...packetRoute(), filter })
  }
  function jump(packet: number) {
    navigate({ ...packetRoute(), packet })
  }
  function storyJump(conversation: Flow, step: StoryStep) {
    navigate({ ...packetRoute(), packet: step.first_packet, scope: conversation.id })
  }
  function header() {
    if (monitor.session)
      return (
        <SessionHeader
          session={monitor.session}
          mock={mock}
          dark={dark}
          toggleTheme={() => setDark((value) => !value)}
          busy={monitor.busy}
          control={(action) => void monitor.control(action)}
        />
      )
    if (monitor.loading) return <Skeleton className="header-skeleton" aria-label={labels.loading} />
    return <h1>netmon</h1>
  }
  return (
    <TooltipProvider delayDuration={200}>
      <main className="app-shell">
        {header()}
        {monitor.error && (
          <Alert variant="destructive">
            <AlertDescription>
              {monitor.error}
              {monitor.failures >= 3 && <p>{labels.backoff}</p>}
              <Button variant="outline" onClick={monitor.refresh}>
                {labels.retry}
              </Button>
            </AlertDescription>
          </Alert>
        )}
        {monitor.session && (
          <Tabs className="app-tabs" value={route.tab} onValueChange={changeTab}>
            <div className="tab-toolbar">
              <TabsList variant="line">
                {(['packets', 'connections', 'alerts', 'glossary'] as const).map((name) => (
                  <TabsTrigger key={name} value={name}>
                    {labels[name]}
                    {name === 'alerts' && monitor.alerts.length > 0 && (
                      <span className="tab-count">{monitor.alerts.length}</span>
                    )}
                  </TabsTrigger>
                ))}
              </TabsList>
              {monitor.session.state !== 'running' && (
                <Button variant="ghost" onClick={monitor.refresh}>
                  {labels.refresh}
                </Button>
              )}
            </div>
            <TabsContent value="packets" className="view-content">
              <PacketsView
                api={api}
                session={monitor.session}
                rows={rows}
                filter={route.filter}
                filterError={monitor.filterError}
                apply={apply}
                selected={selectedPacket}
                select={(packet) => navigate({ ...route, packet })}
                terms={monitor.terms}
                openFlow={(flow) => navigate({ ...route, tab: 'connections', flow })}
                page={monitor.page}
                scope={route.scope}
                clearScope={() => navigate({ ...route, scope: null })}
              />
            </TabsContent>
            <TabsContent value="connections" className="view-content">
              <ConnectionsView
                api={api}
                flows={monitor.flows}
                sort={sort}
                setSort={setSort}
                selected={route.flow}
                select={(flow) => navigate({ ...route, flow })}
                terms={monitor.terms}
                jump={storyJump}
                control={monitor.control}
                revision={monitor.session.packets}
                mock={mock}
                busy={monitor.busy}
              />
            </TabsContent>
            <TabsContent value="alerts" className="view-content scroll-view">
              <AlertsView alerts={monitor.alerts} terms={monitor.terms} jump={jump} />
            </TabsContent>
            <TabsContent value="glossary" className="view-content">
              <GlossaryView
                terms={monitor.terms}
                selected={route.term}
                select={(term) => navigate({ ...route, term })}
              />
            </TabsContent>
          </Tabs>
        )}
      </main>
    </TooltipProvider>
  )
}
