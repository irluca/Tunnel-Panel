import { useEffect, useState } from 'react'
import { useTranslation } from 'react-i18next'
import { useQuery } from '@tanstack/react-query'
import { ArrowLeftRight, AlertTriangle } from 'lucide-react'

import { TunnelType, type Tunnel } from '@/lib/types'
import { tunnelLabel } from '@/lib/format'
import { api } from '@/lib/api'
import { useTunnelActions } from '@/hooks/useTunnelActions'
import { Button } from '../ui/button'
import { ErrorState, Skeleton } from '../ui/feedback'
import {
  Dialog,
  DialogBody,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
} from '../ui/overlay'
import { CopyButton, Technical, TechnicalBlock } from '../ui/technical'

/**
 * Switching a tunnel's carrier — GRE to ESP or ESP to GRE.
 *
 * The dialog states exactly what will happen rather than asking a generic
 * "are you sure": the tunnel is rebuilt on the other carrier, which briefly
 * interrupts it, and if the new carrier does not verify, the previous one
 * comes back. After the switch the operator gets the pairing code for the
 * new carrier: the far end must switch the same way, and without the code it
 * cannot.
 */
export function SwitchCarrierDialog({
  tunnel,
  open,
  onOpenChange,
}: {
  tunnel: Tunnel
  open: boolean
  onOpenChange: (open: boolean) => void
}) {
  const { t } = useTranslation()
  const actions = useTunnelActions()

  const [submitting, setSubmitting] = useState(false)
  const [pairingCode, setPairingCode] = useState<string | null>(null)

  const targetTypeId =
    tunnel.tunnel_type_id === TunnelType.ESP ? TunnelType.GRE : TunnelType.ESP
  const currentLabel = tunnel.tunnel_type_id === TunnelType.ESP ? 'ESP' : 'GRE'
  const targetLabel = targetTypeId === TunnelType.ESP ? 'ESP' : 'GRE'

  // The preview: what the switch would change, fetched when the dialog opens
  // so the operator sees the new name and the new key before committing to a
  // rebuild. A switch the backend would refuse is refused here too, with the
  // same reason — the preview is where the exact rejection reason is shown.
  const previewQuery = useQuery({
    queryKey: ['tunnels', tunnel.tunnel_id, 'switch-preview', targetTypeId],
    queryFn: () =>
      api.post<{
        current_tunnel_type_id: number
        target_tunnel_type_id: number
        interface_name: string
        new_interface_name: string
        name_changes: boolean
        fresh_esp_key: boolean
        gre_key_from_settings: boolean
      }>(`/tunnels/${tunnel.tunnel_id}/switch/preview`, { tunnel_type_id: targetTypeId }),
    enabled: open && !pairingCode,
  })
  const preview = previewQuery.data

  useEffect(() => {
    if (!open) {
      setSubmitting(false)
      setPairingCode(null)
    }
  }, [open ])

  async function confirm() {
    setSubmitting(true)
    const result = await actions.switchCarrier(tunnel.tunnel_id, targetTypeId, tunnelLabel(tunnel))
    setSubmitting(false)
    if (result) {
      setPairingCode(result.pairingCode)
    }
  }

  return (
    <Dialog open={open} onOpenChange={onOpenChange}>
      <DialogContent size="md">
        <DialogHeader>
          <DialogTitle>{t('switch.dialogTitle')}</DialogTitle>
          <DialogDescription>
            {t('switch.dialogBody', { name: tunnelLabel(tunnel), from: currentLabel, to: targetLabel })}
          </DialogDescription>
        </DialogHeader>

        <DialogBody className="space-y-4">
          {pairingCode ? (
            <>
              <p className="text-sm">{t('switch.doneBody', { to: targetLabel })}</p>
              <div className="space-y-1.5">
                <div className="flex items-center justify-between gap-2">
                  <span className="text-xs font-medium">{t('pairing.codeLabel')}</span>
                  <CopyButton value={pairingCode} label={t('pairing.copy')} />
                </div>
                <TechnicalBlock className="max-h-32 whitespace-pre-wrap break-all">{pairingCode}</TechnicalBlock>
              </div>
              <p dir="auto" className="text-2xs text-muted-foreground">{t('switch.peerBody')}</p>
            </>
          ) : (
            <>
              <div className="flex items-center gap-3 rounded-md border border-border bg-muted/50 px-3 py-2.5">
                <Technical>{currentLabel}</Technical>
                <ArrowLeftRight className="size-4 shrink-0 text-muted-foreground" aria-hidden="true" />
                <Technical>{targetLabel}</Technical>
              </div>
              {previewQuery.isLoading ? (
                <Skeleton className="h-16" />
              ) : previewQuery.error ? (
                <ErrorState error={previewQuery.error} onRetry={() => void previewQuery.refetch()} compact />
              ) : preview ? (
                <dl className="space-y-1.5 text-xs">
                  {preview.name_changes ? (
                    <div className="flex items-center gap-2">
                      <dt className="text-muted-foreground">{t('switch.preview.newName')}</dt>
                      <dd className="flex items-center gap-2">
                        <Technical>{preview.interface_name}</Technical>
                        <ArrowLeftRight className="size-3 text-muted-foreground" aria-hidden="true" />
                        <Technical>{preview.new_interface_name}</Technical>
                      </dd>
                    </div>
                  ) : (
                    <div className="flex items-center gap-2">
                      <dt className="text-muted-foreground">{t('switch.preview.nameStays')}</dt>
                      <dd>
                        <Technical>{preview.interface_name}</Technical>
                      </dd>
                    </div>
                  )}
                  {preview.fresh_esp_key ? (
                    <p className="text-muted-foreground">{t('switch.preview.freshEspKey')}</p>
                  ) : null}
                  {preview.gre_key_from_settings ? (
                    <p className="text-muted-foreground">{t('switch.preview.greKeyFromSettings')}</p>
                  ) : null}
                </dl>
              ) : null}
              <p className="flex items-start gap-2 text-xs text-muted-foreground">
                <AlertTriangle className="mt-0.5 size-4 shrink-0" aria-hidden="true" />
                {t('switch.warning')}
              </p>
            </>
          )}
        </DialogBody>

        <DialogFooter>
          <Button variant="secondary" onClick={() => onOpenChange(false)}>
            {pairingCode ? t('actions.close') : t('actions.cancel')}
          </Button>
          {!pairingCode ? (
            <Button loading={submitting} onClick={() => void confirm()}>
              {t('switch.confirm', { to: targetLabel })}
            </Button>
          ) : null}
        </DialogFooter>
      </DialogContent>
    </Dialog>
  )
}
