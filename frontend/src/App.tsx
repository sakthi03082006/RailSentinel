import { useEffect, useState } from "react";
import "./App.css";

type SecurityEvent = {
  id: string;
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
    object_type?: string;
    explanation?: string;
    route_information?: {
      waypoint_name?: string;
      simulated_data?: boolean;
    };
  };
};

type WebSocketMessage = {
  type: string;
  event?: SecurityEvent;
};

const MAP_LAT_MIN = 28.6135;
const MAP_LAT_MAX = 28.6150;
const MAP_LON_MIN = 77.2085;
const MAP_LON_MAX = 77.2105;

function getMapCoords(lat: number | string, lon: number | string) {
  const numLat = Number(lat);
  const numLon = Number(lon);

  if (isNaN(numLat) || isNaN(numLon)) {
    return { top: '50%', left: '50%' };
  }

  const y = 100 - ((numLat - MAP_LAT_MIN) / (MAP_LAT_MAX - MAP_LAT_MIN)) * 100;
  const x = ((numLon - MAP_LON_MIN) / (MAP_LON_MAX - MAP_LON_MIN)) * 100;
  return { top: `${Math.max(5, Math.min(95, y))}%`, left: `${Math.max(5, Math.min(95, x))}%` };
}

export default function App() {
  const [events, setEvents] = useState<SecurityEvent[]>([]);
  const [loading, setLoading] = useState(true);
  const [liveConnected, setLiveConnected] = useState(false);
  const [selectedEventId, setSelectedEventId] = useState<string | null>(null);

  useEffect(() => {
    const loginAndLoadEvents = async () => {
      try {
        const loginResponse = await fetch("http://localhost:8000/api/v1/auth/login", {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ username: "admin", password: "admin" })
        });

        if (!loginResponse.ok) throw new Error("Login failed");

        const { access_token } = await loginResponse.json();
        const eventsResponse = await fetch("http://localhost:8000/api/v1/events", {
          headers: { Authorization: `Bearer ${access_token}` }
        });

        if (!eventsResponse.ok) throw new Error(`Failed: ${eventsResponse.status}`);

        const data = await eventsResponse.json();
        setEvents(data.items ?? data);
      } catch (error) {
        console.error("RailSentinel connection error:", error);
      } finally {
        setLoading(false);
      }
    };
    loginAndLoadEvents();
  }, []);

  useEffect(() => {
    const websocket = new WebSocket("ws://localhost:8000/ws/events");

    const connectWS = () => {
      websocket.onopen = () => setLiveConnected(true);
      websocket.onmessage = (message) => {
        try {
          const data: WebSocketMessage = JSON.parse(message.data);
          if (data.type === "security_event" && data.event) {
            setEvents(current => {
              if (current.some(e => e.id === data.event?.id)) return current;
              return [data.event!, ...current];
            });
          }
        } catch (err) { }
      };
      websocket.onclose = () => setLiveConnected(false);
      websocket.onerror = () => setLiveConnected(false);
    };

    connectWS();
    return () => websocket.close();
  }, []);

  const activeAlerts = events.filter(e => e.status === "NEW");
  const criticalThreats = events.filter(e => e.severity_band === "RED");
  const uniqueDevices = new Set(events.filter(e => e.device_id).map(e => e.device_id)).size || 1;
  const patrolEvents = events.filter(e => e.lat && e.lon).slice(0, 10);
  const latestPatrol = patrolEvents.length > 0 ? patrolEvents[0] : null;

  const selectedEvent = events.find(e => e.id === selectedEventId) || null;

  if (loading) {
    return <div className="app-container loading-screen">ESTABLISHING SECURE CONNECTION...</div>;
  }

  return (
    <div className="app-container">
      {/* HEADER */}
      <header className="app-header">
        <div className="brand-section">
          <h1>RailSentinel</h1>
          <span className="brand-subtitle">AI-POWERED RAILWAY SECURITY & THREAT RESPONSE</span>
        </div>
        <div className={`status-indicator ${liveConnected ? 'online' : ''}`}>
          <div className="pulse" />
          {liveConnected ? "SYSTEM LIVE" : "OFFLINE"}
        </div>
      </header>

      <main className="dashboard-main">
        {/* KPI CARDS */}
        <section className="kpi-grid">
          <div className="kpi-card critical">
            <span className="kpi-label">RED EVENTS</span>
            <span className="kpi-value">{criticalThreats.length}</span>
          </div>
          <div className="kpi-card warning">
            <span className="kpi-label">NEW ALERTS</span>
            <span className="kpi-value">{activeAlerts.length}</span>
          </div>
          <div className="kpi-card active">
            <span className="kpi-label">ACTIVE DEVICES</span>
            <span className="kpi-value">{Math.max(uniqueDevices, 1)}</span>
          </div>
          <div className="kpi-card">
            <span className="kpi-label">TOTAL EVENTS</span>
            <span className="kpi-value">{events.length}</span>
          </div>
        </section>

        {/* MAIN PANELS */}
        <section className="content-panels">
          <div className="center-column">
            {/* MAP PANEL */}
            <div className="panel ops-map-panel">
              <div className="panel-header">
                <h2>Live Security Map</h2>
                {latestPatrol && latestPatrol.lat !== undefined && latestPatrol.lon !== undefined && (
                  <span className="map-coord-display">
                    P-LOC: {!isNaN(Number(latestPatrol.lat)) && !isNaN(Number(latestPatrol.lon))
                      ? `${Number(latestPatrol.lat).toFixed(4)}, ${Number(latestPatrol.lon).toFixed(4)}`
                      : '—'}
                  </span>
                )}
              </div>
              <div className="panel-content ops-map">
                <div className="simulated-label">SIMULATED GPS DATA</div>
                <div className="map-legend">
                  <div className="legend-item"><div className="marker-point marker-patrol"></div> Patrol</div>
                  <div className="legend-item"><div className="marker-point marker-red"></div> Threat</div>
                </div>

                {/* Map Path Simulation (SVG overlay) */}
                {patrolEvents.length > 1 && (
                  <svg className="map-path-svg">
                    <polyline
                      points={patrolEvents.map(e => {
                        const { left, top } = getMapCoords(e.lat!, e.lon!);
                        return `${parseFloat(left)},${parseFloat(top)}`;
                      }).join(' ')}
                      fill="none"
                      stroke="rgba(88, 166, 255, 0.4)"
                      strokeWidth="2"
                      strokeDasharray="4 4"
                    />
                  </svg>
                )}

                {events.slice(0, 20).map(evt => {
                  if (!evt.lat || !evt.lon) return null;
                  const pos = getMapCoords(evt.lat, evt.lon);
                  let colorClass = "marker-patrol";
                  if (evt.severity_band === "RED") colorClass = "marker-red";
                  else if (evt.severity_band === "YELLOW") colorClass = "marker-yellow";
                  else if (evt.event_type !== "patrol") colorClass = "marker-green";

                  return (
                    <div
                      key={evt.id}
                      className={`map-marker ${selectedEventId === evt.id ? 'selected' : ''}`}
                      style={pos}
                      onClick={() => setSelectedEventId(evt.id)}
                    >
                      <div className={`marker-point ${colorClass}`} />
                      {evt.severity_band === "RED" && (
                        <div className="marker-detail">
                          {evt.payload?.object_type || "Threat"} ({Number(evt.threat_score).toFixed(0)})
                        </div>
                      )}
                    </div>
                  );
                })}
              </div>
            </div>

            {/* EVENT DETAIL (Conditional) */}
            {selectedEvent && (
              <div className="panel detail-panel">
                <div className="panel-header detail-header">
                  <h2>Incident Detail</h2>
                  <button className="close-btn" onClick={() => setSelectedEventId(null)}>×</button>
                </div>
                <div className="panel-content detail-content">
                  <div className="detail-top-row">
                    <span className={`severity-badge severity-${selectedEvent.severity_band?.toLowerCase() || 'green'}`}>
                      {selectedEvent.severity_band === 'RED' ? 'CRITICAL / RED' : selectedEvent.severity_band}
                    </span>
                    <span className="detail-score">Score: {Number(selectedEvent.threat_score).toFixed(1)}</span>
                  </div>

                  <div className="detail-grid">
                    <div className="d-group">
                      <label>Event Type</label>
                      <div>{selectedEvent.event_type.replace(/_/g, ' ')}</div>
                    </div>
                    <div className="d-group">
                      <label>Object Type</label>
                      <div>{selectedEvent.payload?.object_type || 'N/A'}</div>
                    </div>
                    <div className="d-group">
                      <label>Timestamp</label>
                      <div>{selectedEvent.created_at ? new Date(selectedEvent.created_at).toLocaleString() : 'Processing...'}</div>
                    </div>
                    <div className="d-group">
                      <label>Confidence</label>
                      <div>{selectedEvent.confidence !== undefined ? `${(selectedEvent.confidence * 100).toFixed(0)}%` : 'N/A'}</div>
                    </div>
                    <div className="d-group">
                      <label>Location</label>
                      <div>{selectedEvent.payload?.route_information?.waypoint_name || 'N/A'}</div>
                    </div>
                    <div className="d-group">
                      <label>Status</label>
                      <div>{selectedEvent.status}</div>
                    </div>
                    <div className="d-group col-span-2">
                      <label>Device Source</label>
                      <div>{selectedEvent.device_id || 'Unknown Device'}</div>
                    </div>
                    <div className="d-group col-span-2">
                      <label>GPS Coordinates</label>
                      <div>{selectedEvent.lat && selectedEvent.lon ? `${selectedEvent.lat}, ${selectedEvent.lon} (Simulated)` : 'Not provided'}</div>
                    </div>
                    {selectedEvent.payload?.explanation && (
                      <div className="d-group col-span-2">
                        <label>AI Explanation</label>
                        <div className="explanation-text">{selectedEvent.payload.explanation}</div>
                      </div>
                    )}
                  </div>
                </div>
              </div>
            )}
          </div>

          {/* EVENT FEED */}
          <div className="panel feed-panel">
            <div className="panel-header">
              <h2>Live Threat Feed</h2>
            </div>
            <div className="panel-content event-feed">
              {events.length === 0 ? (
                <div style={{ padding: '20px', color: '#8b949e' }}>No telemetry received.</div>
              ) : (
                events.map(event => {
                  const isRed = event.severity_band === "RED";
                  const isCritical = event.severity_band === "RED";
                  const dateStr = event.created_at ? new Date(event.created_at).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit', second: '2-digit' }) : "";
                  const confidenceDisplay = event.confidence !== undefined ? ` • Conf ${Math.round(event.confidence * 100)}%` : '';
                  const locationDisplay = event.payload?.route_information?.waypoint_name
                    || (event.lat !== undefined && !isNaN(Number(event.lat)) ? `GPS: ${Number(event.lat).toFixed(4)}, ${Number(event.lon).toFixed(4)}` : '');
                  const isSelected = selectedEventId === event.id;

                  return (
                    <div
                      key={event.id}
                      className={`event-item ${isRed ? 'event-red' : ''} ${isSelected ? 'selected' : ''}`}
                      onClick={() => setSelectedEventId(event.id)}
                    >
                      <div className="feed-row-top">
                        <span className={`severity-badge severity-${event.severity_band?.toLowerCase() || 'green'}`}>
                          {isCritical ? 'CRITICAL / RED' : event.severity_band}
                        </span>
                        <span className="feed-title">{event.payload?.object_type || event.event_type.replace(/_/g, ' ')}</span>
                      </div>

                      {locationDisplay && (
                        <div className="feed-row-mid">
                          <span className="feed-lbl">LOC</span> {locationDisplay}
                        </div>
                      )}

                      <div className="feed-row-mid" style={{ color: isRed ? '#ff7b72' : '#c9d1d9', fontWeight: 600 }}>
                        Score {Number(event.threat_score).toFixed(0)}{confidenceDisplay}
                      </div>

                      <div className="feed-row-bottom">
                        {event.device_id ? `Source: ${event.device_id.split('-')[0]}` : 'Patrol Unit'}  • {dateStr}
                      </div>
                    </div>
                  );
                })
              )}
            </div>
          </div>
        </section>

      </main>
    </div>
  );
}