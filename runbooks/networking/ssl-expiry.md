# SSL Certificate Expiry

## Symptoms
- Alert: certificate expires in < 14 days
- Browsers showing security warnings
- Internal services failing TLS handshake

## Immediate Actions
1. **Verify current certificate**:
   ```bash
   echo | openssl s_client -connect <domain>:443 -servername <domain> 2>/dev/null | openssl x509 -noout -dates
   ```
2. **Trigger cert-manager renewal** (if using cert-manager):
   ```bash
   kubectl annotate certificate <cert-name> -n <namespace> cert-manager.io/force-renew=true
   ```
3. **Emergency manual renewal** (if cert-manager fails):
   ```bash
   certbot certonly --standalone -d <domain>
   kubectl create secret tls <secret-name> --cert=fullchain.pem --key=privkey.pem -n <namespace>
   ```

## Validation
- `openssl s_client` shows new expiry date > 60 days
- No browser warnings on the domain
- Internal TLS connections succeed

## Prevention
- Set cert-manager to renew at 30 days before expiry
- Alert at 14 days and 7 days
- Automate certificate rotation in CI/CD
