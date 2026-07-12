# CPU Throttling in Kubernetes

## Symptoms
- Pod CPU usage hitting limits, causing request latency spikes
- `container_cpu_cfs_throttled_seconds_total` increasing in Prometheus
- P99 latency degrading while P50 remains stable

## Immediate Actions
1. **Check current CPU limits**:
   ```bash
   kubectl get deployment <deployment> -n <namespace> -o jsonpath='{.spec.template.spec.containers[0].resources}'
   ```
2. **Temporarily increase CPU limits** (requires approval):
   ```bash
   kubectl patch deployment <deployment> -n <namespace> -p '{"spec":{"template":{"spec":{"containers":[{"name":"app","resources":{"limits":{"cpu":"2000m"}}}]}}}}'
   ```
3. **Check for noisy neighbors**:
   ```bash
   kubectl top pods -n <namespace>
   ```

## Validation
- Throttled seconds metric should drop to near zero
- P99 latency should return to baseline within 5 minutes

## Prevention
- Set CPU requests = limits for latency-sensitive services
- Use VPA (Vertical Pod Autoscaler) to right-size resources
- Add throttling alerts at 50% throttled time ratio
