export type SecurityEvent = {
  id: string;
  latest_event_id?: string;
  event_type: string;
  severity_band: string;
  threat_score: number;
  confidence?: number;
  status: string;
  lat?: number | string;
  lon?: number | string;
  created_at?: string;
  occurred_at?: string;
  device_id?: string;
  payload?: {
    incident_id?: string;
    track_id?: string;
    is_escalation?: boolean;
    object_type?: string;
    explanation?: string;
    evidence?: {
      object_type?: string;
      dwell_seconds?: number;
      person_left_object?: boolean;
      detection_source?: string;
      track_id?: string;
    };
    route_information?: {
      waypoint_name?: string;
      simulated_data?: boolean;
    };
  };
};

/**
 * Checks whether two events represent the same physical active incident.
 * Conservative rules:
 * 1. Direct event ID match.
 * 2. Primary: explicit incident_id match.
 * 3. Fallback: track_id match ONLY when guaranteed from the same device/source.
 * 4. Events without explicit identifiers are NEVER merged.
 */
export function isSameIncident(existing: SecurityEvent, incoming: SecurityEvent): boolean {
  if (existing.id === incoming.id || existing.latest_event_id === incoming.id) {
    return true;
  }

  // Primary: explicit incident_id match
  const existingIncidentId = existing.payload?.incident_id;
  const incomingIncidentId = incoming.payload?.incident_id;
  if (existingIncidentId && incomingIncidentId && existingIncidentId === incomingIncidentId) {
    return true;
  }

  // Fallback: track_id match ONLY where guaranteed to represent the same active camera track
  const existingTrackId = existing.payload?.track_id || existing.payload?.evidence?.track_id;
  const incomingTrackId = incoming.payload?.track_id || incoming.payload?.evidence?.track_id;

  if (existingTrackId && incomingTrackId && existingTrackId === incomingTrackId) {
    const existingDevice = existing.device_id || existing.payload?.evidence?.detection_source;
    const incomingDevice = incoming.device_id || incoming.payload?.evidence?.detection_source;
    if (existingDevice && incomingDevice && existingDevice === incomingDevice) {
      return true;
    }
  }

  return false;
}

/**
 * In-place update/escalation for incoming WebSocket events.
 * If incoming event belongs to an existing active incident, updates the incident in place
 * (escalating to RED, updating score and explanation) without creating a second incident card.
 */
export function updateEventsWithIncoming(
  current: SecurityEvent[],
  incoming: SecurityEvent
): SecurityEvent[] {
  const existingIdx = current.findIndex(e => isSameIncident(e, incoming));

  if (existingIdx !== -1) {
    const existing = current[existingIdx];
    const updatedIncident: SecurityEvent = {
      ...existing,
      ...incoming,
      id: existing.id,
      latest_event_id: incoming.id,
      severity_band: incoming.severity_band,
      threat_score: incoming.threat_score,
      status: incoming.status || existing.status,
      confidence: incoming.confidence !== undefined ? incoming.confidence : existing.confidence,
      occurred_at: incoming.occurred_at || existing.occurred_at,
      created_at: incoming.created_at || existing.created_at,
      payload: {
        ...existing.payload,
        ...incoming.payload,
        object_type:
          incoming.payload?.object_type ||
          incoming.payload?.evidence?.object_type ||
          existing.payload?.object_type,
        explanation: incoming.payload?.explanation || existing.payload?.explanation,
        incident_id: incoming.payload?.incident_id || existing.payload?.incident_id,
        track_id: incoming.payload?.track_id || existing.payload?.track_id,
      },
    };

    const nextEvents = [...current];
    nextEvents[existingIdx] = updatedIncident;
    return nextEvents;
  }

  // Brand new incident
  return [incoming, ...current];
}

/**
 * Conservative historical event consolidation on initial load.
 * Only merges events that share explicit incident_id or guaranteed device+track_id.
 * Preserves historical events without explicit identifiers as separate items.
 */
export function consolidateHistoricalEvents(events: SecurityEvent[]): SecurityEvent[] {
  const consolidated: SecurityEvent[] = [];

  for (const event of events) {
    const hasIncidentId = Boolean(event.payload?.incident_id);
    const hasTrackId = Boolean(event.payload?.track_id || event.payload?.evidence?.track_id);

    if (!hasIncidentId && !hasTrackId) {
      // Conservative: preserve historical events without explicit identifiers as separate items
      consolidated.push(event);
      continue;
    }

    const matchIdx = consolidated.findIndex(c => isSameIncident(c, event));
    if (matchIdx !== -1) {
      const current = consolidated[matchIdx];
      // Keep higher severity / threat score
      if (Number(event.threat_score) >= Number(current.threat_score)) {
        consolidated[matchIdx] = {
          ...current,
          ...event,
          payload: {
            ...current.payload,
            ...event.payload,
          },
        };
      }
    } else {
      consolidated.push(event);
    }
  }

  return consolidated;
}
