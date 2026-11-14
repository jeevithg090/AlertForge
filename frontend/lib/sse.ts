'use client';

/**
 * React hooks over the backend's Server-Sent Events streams.
 *
 * `EventSource` cannot send an Authorization header, so the stored JWT (if any)
 * is passed as the `access_token` query parameter, which the backend accepts on
 * the stream endpoints only.
 */

import { useEffect, useRef, useState } from 'react';
import { apiUrl, getToken } from './api';

/** A dashboard event. Every event carries `type`; the rest depends on the type. */
// eslint-disable-next-line @typescript-eslint/no-explicit-any
export type SSEEvent = { type: string; incident_id?: string; [key: string]: any };

function streamUrl(path: string): string {
  const token = getToken();
  const url = apiUrl(path);
  return token ? `${url}?access_token=${encodeURIComponent(token)}` : url;
}

export type SSEHandler = (evt: SSEEvent) => void;

/**
 * Subscribe to an SSE endpoint. `onEvent` is invoked once per event, in order;
 * use functional state updates inside it. Returns the connection state.
 */
function useEventStream(path: string | null, onEvent?: SSEHandler) {
  const [connected, setConnected] = useState(false);
  const onEventRef = useRef(onEvent);
  onEventRef.current = onEvent;

  useEffect(() => {
    if (!path || typeof window === 'undefined' || !('EventSource' in window)) return;
    // EventSource reconnects on its own and resends Last-Event-ID, which the
    // per-incident endpoint uses to replay missed events.
    const source = new EventSource(streamUrl(path));
    source.onopen = () => setConnected(true);
    source.onerror = () => setConnected(false);
    source.onmessage = (msg: MessageEvent<string>) => {
      let evt: SSEEvent;
      try {
        evt = JSON.parse(msg.data);
      } catch {
        return;
      }
      if (!evt || typeof evt.type !== 'string') return;
      onEventRef.current?.(evt);
    };
    return () => {
      source.close();
      setConnected(false);
    };
  }, [path]);

  return { connected };
}

/** Live events for every incident (dashboard feed). */
export function useAllIncidentsStream(onEvent?: SSEHandler) {
  return useEventStream('/api/v1/incidents/stream/all', onEvent);
}

/** Live events for one incident, plus the accumulated reasoning trace. */
export function useIncidentStream(incidentId: string | undefined, onEvent?: SSEHandler) {
  const [thinkingChunks, setThinkingChunks] = useState<string[]>([]);

  useEffect(() => {
    setThinkingChunks([]);
  }, [incidentId]);

  const { connected } = useEventStream(
    incidentId ? `/api/v1/incidents/${encodeURIComponent(incidentId)}/stream` : null,
    evt => {
      if (evt.type === 'thinking.chunk') {
        const text = evt.content ?? evt.text;
        if (typeof text === 'string' && text) setThinkingChunks(prev => [...prev, text]);
      }
      onEvent?.(evt);
    },
  );

  return { thinkingChunks, connected };
}
