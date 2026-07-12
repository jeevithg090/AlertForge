# Memory Leak — Java Service

## Symptoms
- RSS memory usage climbing steadily past 80% of container limit
- Increasing GC pause times visible in JVM metrics
- Eventually OOMKilled by Kubernetes

## Immediate Actions
1. **Collect heap dump** (non-destructive):
   ```bash
   kubectl exec -it <pod> -- jmap -dump:format=b,file=/tmp/heap.hprof 1
   kubectl cp <pod>:/tmp/heap.hprof ./heap.hprof
   ```
2. **Restart the pod** to restore service (requires approval):
   ```bash
   kubectl rollout restart deployment/<deployment> -n <namespace>
   ```
3. **Pin to previous version** if the leak was introduced in a recent deploy:
   ```bash
   kubectl rollout undo deployment/<deployment> -n <namespace>
   ```

## Validation
- Memory usage should drop to baseline (<4GB) within 2 minutes of restart
- GC pause times should return to <100ms
- No OOMKilled events in the next 30 minutes

## Root Cause Investigation
- Analyze heap dump with Eclipse MAT or VisualVM
- Look for large object graphs, unclosed connections, or cache growth
- Check if the leak correlates with a specific code change

## Prevention
- Add JVM memory alerts at 70% and 85% thresholds
- Implement heap dump on OOM: `-XX:+HeapDumpOnOutOfMemoryError`
- Add integration tests that run under memory pressure
