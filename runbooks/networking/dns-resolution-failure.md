# DNS Resolution Failure

## Symptoms
- Services unable to resolve internal or external hostnames
- CoreDNS error rate spiking in Prometheus
- `NXDOMAIN` or `SERVFAIL` responses increasing

## Immediate Actions
1. **Check CoreDNS pods**:
   ```bash
   kubectl get pods -n kube-system -l k8s-app=kube-dns
   kubectl logs -n kube-system -l k8s-app=kube-dns --tail=50
   ```
2. **Test DNS resolution from a pod**:
   ```bash
   kubectl run debug --image=busybox --rm -it -- nslookup kubernetes.default
   ```
3. **Check upstream DNS servers**:
   ```bash
   kubectl get configmap coredns -n kube-system -o yaml
   ```
4. **Restart CoreDNS** (requires approval):
   ```bash
   kubectl rollout restart deployment/coredns -n kube-system
   ```

## Validation
- `nslookup` returns valid IPs for internal services
- CoreDNS error rate drops to baseline
- Application services can reach external dependencies

## Prevention
- Monitor CoreDNS cache hit ratio and error rate
- Configure multiple upstream DNS servers for redundancy
- Use NodeLocal DNSCache for high-throughput clusters
