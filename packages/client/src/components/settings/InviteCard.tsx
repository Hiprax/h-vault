import { useState } from 'react';
import { Clipboard, UserPlus } from 'lucide-react';
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '../ui/Card';
import { Button } from '../ui/Button';
import { Input } from '../ui/Input';
import { Label } from '../ui/Label';
import { FormAlert } from '../ui/FormAlert';
import { useToast } from '../ui/Toast';
import { getApiErrorMessage } from '../../lib/utils';
import { proveMasterPassword } from '../../lib/masterPasswordProof';
import { createInvitationApi } from '../../services/api/authApi';
import { copySecretToClipboard } from '../../services/clipboard/clipboardService';

interface InviteCardProps {
  /** This account's address: the salt its master-password proof is derived with. */
  email: string;
  /** The account's clipboard clear delay, in seconds, for copying the link. */
  clipboardClearSeconds: number;
}

/**
 * Lets an inviting account (listed by the operator in `REGISTRATION_INVITERS`,
 * on a server whose `REGISTRATION_MODE` is `invite`) mint an invitation for one
 * address.
 *
 * The master password is proven the way every other sensitive action proves it:
 * derived in the browser, hashed, and the derived key zeroed. The link comes back
 * once and is shown here once; it is the invitation, so it is copied through the
 * clipboard service like any other secret. H-Vault never mails it: the inviter
 * hands it over.
 */
export function InviteCard({ email, clipboardClearSeconds }: InviteCardProps) {
  const { toast } = useToast();
  const [invitee, setInvitee] = useState('');
  const [password, setPassword] = useState('');
  const [minting, setMinting] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [minted, setMinted] = useState<{ link: string; expiresAt: string } | null>(null);

  const handleMint = async () => {
    setError(null);
    // `<input type="email">` strips only ASCII whitespace; `trim()` also takes
    // the no-break spaces a pasted address often carries.
    const address = invitee.trim();
    if (address === '' || password === '') {
      setError('Enter the address to invite and your master password.');
      return;
    }
    setMinting(true);
    setMinted(null);
    try {
      const authHash = await proveMasterPassword(password, email);
      const res = await createInvitationApi({ authHash, email: address });
      const body = res.data;
      if (body.success) {
        setMinted(body.data);
        setInvitee('');
      }
    } catch (err) {
      setError(getApiErrorMessage(err, 'The invitation could not be created.'));
    } finally {
      // The password never outlives the request, whatever its outcome.
      setPassword('');
      setMinting(false);
    }
  };

  const handleCopy = async (link: string) => {
    try {
      await copySecretToClipboard(link, clipboardClearSeconds * 1000);
      toast({ title: 'Invitation link copied', type: 'success', duration: 2000 });
    } catch {
      toast({ title: 'Failed to copy the invitation link', type: 'error' });
    }
  };

  return (
    <Card>
      <CardHeader>
        <CardTitle className="flex items-center gap-2">
          <UserPlus className="h-5 w-5" />
          Invite someone
        </CardTitle>
        <CardDescription>
          This server registers by invitation. An invitation admits one address, once, within 7
          days. Hand the link over yourself: H-Vault never emails it.
        </CardDescription>
      </CardHeader>
      <CardContent className="space-y-4">
        {error && <FormAlert message={error} />}
        <div className="space-y-2">
          <Label htmlFor="invite-email">Invitee email</Label>
          <Input
            id="invite-email"
            type="email"
            autoComplete="off"
            value={invitee}
            onChange={(e) => setInvitee(e.target.value)}
          />
        </div>
        <div className="space-y-2">
          <Label htmlFor="invite-password">Your master password</Label>
          <Input
            id="invite-password"
            type="password"
            autoComplete="current-password"
            value={password}
            onChange={(e) => setPassword(e.target.value)}
          />
        </div>
        <Button type="button" loading={minting} onClick={() => void handleMint()}>
          Create invitation
        </Button>

        {minted && (
          <div className="space-y-2 rounded-md border border-[hsl(var(--border))] p-3">
            <Label htmlFor="invite-link">Invitation link</Label>
            <div className="flex gap-2">
              <Input id="invite-link" readOnly value={minted.link} className="font-mono text-xs" />
              <Button
                type="button"
                variant="outline"
                aria-label="Copy invitation link"
                onClick={() => void handleCopy(minted.link)}
              >
                <Clipboard className="h-4 w-4" />
              </Button>
            </div>
            <p className="text-xs text-[hsl(var(--muted-foreground))]">
              This link is shown once and works until {new Date(minted.expiresAt).toLocaleString()}.
              Anyone holding it can register that address, so send it only to the person you
              invited.
            </p>
          </div>
        )}
      </CardContent>
    </Card>
  );
}
