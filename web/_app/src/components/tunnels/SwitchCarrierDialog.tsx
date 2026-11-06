import { useEffect, useState } from 'react'
import { useTranslation } from 'react-i18next'
import { ArrowLeftRight, AlertTriangle } from 'lucide-react'

import { TunnelType, type Tunnel } from '@/lib/types'
import { tunnelLabel } from '@/lib/format'
import { useTunnelActions } from '@/hooks/useTunnelActions'
import { Button } from '../ui/button'
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
