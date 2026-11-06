import { useQuery } from '@tanstack/react-query'
import { useTranslation } from 'react-i18next'
import { CheckCircle2, Network, XCircle } from 'lucide-react'

import { api } from '@/lib/api'
import { formatDuration } from '@/lib/format'
import { usePreferences } from '@/providers/PreferencesProvider'
import { Card, CardContent, CardHeader, CardTitle } from '../ui/card'
import { EmptyState, ErrorState, Skeleton } from '../ui/feedback'
import { Technical } from '../ui/technical'

export interface ClusterPeerStatus {
  name: string
  url: string
  reachable: boolean
  status?: string
  version?: string
  uptime_seconds?: number
  error?: string
  checked_at: string
}

/**
 * The cluster, from here: the other panel instances this one is deployed
 * with, and what each one answered. It is a view, not a control plane — one
 * panel never changes another's tunnels. It renders nothing when no peers
 * are configured, because a single panel is not a cluster.
 */
export function ClusterCard() {
  const { t } = useTranslation()
  const { digits } = usePreferences()

  const peersQuery = useQuery({
    queryKey: ['cluster', 'peers'],
    queryFn: () => api.get<{ peers: ClusterPeerStatus[] }>('/cluster/peers'),
    refetchInterval: 30000,
  })

  const peers = peersQuery.data?.peers ?? []
  if (!peersQuery.isLoading && !peersQuery.error && peers.length === 0) return null

  return (
    <Card>
      <CardHeader>
        <CardTitle className="flex items-center gap-2">
          <Network className="size-4 text-muted-foreground" aria-hidden="true" />
          {t('cluster.title')}
        </CardTitle>
      </CardHeader>
      <CardContent>
        {peersQuery.isLoading ? (
          <Skeleton className="h-16" />
        ) : peersQuery.error ? (
          <ErrorState error={peersQuery.error} onRetry={() => void peersQuery.refetch()} compact />
        ) : peers.length === 0 ? (
          <EmptyState title={t('cluster.empty')} />
        ) : (
          <ul className="space-y-2">
            {peers.map((peer) => (
              <li key={peer.name} className="flex items-start gap-2 text-sm">
                {peer.reachable ? (
                  <CheckCircle2 className="mt-0.5 size-4 shrink-0 text-success" aria-hidden="true" />
                ) : (
                  <XCircle className="mt-0.5 size-4 shrink-0 text-danger" aria-hidden="true" />
                )}
                <div className="min-w-0">
                  <p className="font-medium">{peer.name}</p>
                  <p className="text-2xs text-muted-foreground">
                    <Technical>{peer.url}</Technical>
                  </p>
                  {peer.reachable ? (
                    <p className="text-2xs text-muted-foreground">
                      {peer.version ? t('cluster.version', { version: peer.version }) : null}
                      {peer.uptime_seconds != null
                        ? ` · ${formatDuration(peer.uptime_seconds, digits, { day: t('units.day'), hour: t('units.hour'), minute: t('units.minute'), second: t('units.second') })}`
                        : null}
                    </p>
                  ) : (
                    <p dir="auto" className="text-2xs text-danger">
                      {peer.error ?? t('cluster.unreachable')}
                    </p>
                  )}
                </div>
              </li>
            ))}
          </ul>
        )}
      </CardContent>
    </Card>
  )
}
