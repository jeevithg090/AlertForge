# Database Connection Pool Exhaustion

## Symptoms
- Application errors: "connection pool exhausted", "too many connections"
- PostgreSQL `pg_stat_activity` showing connections near `max_connections`
- Increasing query latency and timeout errors

## Immediate Actions
1. **Check current connection count**:
   ```sql
   SELECT count(*) FROM pg_stat_activity;
   SELECT count(*) FROM pg_stat_activity WHERE state = 'idle';
   ```
2. **Identify connection hogs**:
   ```sql
   SELECT usename, application_name, count(*)
   FROM pg_stat_activity
   GROUP BY usename, application_name
   ORDER BY count DESC;
   ```
3. **Kill idle connections** (requires approval):
   ```sql
   SELECT pg_terminate_backend(pid)
   FROM pg_stat_activity
   WHERE state = 'idle' AND state_change < NOW() - INTERVAL '10 minutes';
   ```
4. **Restart application pods** to reset connection pools (requires approval):
   ```bash
   kubectl rollout restart deployment/<app> -n <namespace>
   ```
5. **Increase max_connections** if needed (requires DBA approval):
   ```sql
   ALTER SYSTEM SET max_connections = 300;
   SELECT pg_reload_conf();
   ```

## Validation
- Active connections drop below 70% of max_connections
- Application error rate returns to baseline
- Query latency normalizes (<100ms P99)

## Prevention
- Deploy PgBouncer as a connection pooler in front of PostgreSQL
- Set application connection pool max to max_connections / number_of_services
- Add connection pool usage alerts at 70% and 85% thresholds
- Implement connection timeout and idle connection eviction in application code
