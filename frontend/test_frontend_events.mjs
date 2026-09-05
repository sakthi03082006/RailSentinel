import assert from "node:assert";
import { updateEventsWithIncoming, consolidateHistoricalEvents, isSameIncident } from "./src/eventUtils.ts";

console.log("--- Running Frontend Incident Lifecycle Regression Tests ---");

// Test 1: Repeated frames of the same track / event ID -> no duplicate
const initialYellow = {
  id: "evt-001",
  event_type: "unattended_object",
  severity_band: "YELLOW",
  threat_score: 50.0,
  confidence: 0.88,
  status: "NEW",
  device_id: "device-cctv-01",
  payload: {
    incident_id: "inc-100",
    track_id: "track_1",
    object_type: "backpack",
    explanation: "Person observed leaving object.",
    evidence: {
      object_type: "backpack",
      dwell_seconds: 10.0,
      person_left_object: true,
      track_id: "track_1",
    }
  }
};

let state = updateEventsWithIncoming([], initialYellow);
assert.strictEqual(state.length, 1, "Initial incident added");
assert.strictEqual(state[0].severity_band, "YELLOW");
assert.strictEqual(state[0].threat_score, 50.0);

// Repeated incoming frame with same event ID or same incident_id -> still 1 incident
state = updateEventsWithIncoming(state, initialYellow);
assert.strictEqual(state.length, 1, "Repeated frame does not duplicate incident");

// Test 2: YELLOW -> RED Escalation of the same incident
// Incoming escalation has new event ID evt-002, but same incident_id "inc-100" and track_id "track_1"
const redEscalation = {
  id: "evt-002",
  event_type: "unattended_object",
  severity_band: "RED",
  threat_score: 70.0,
  confidence: 0.88,
  status: "NEW",
  device_id: "device-cctv-01",
  payload: {
    incident_id: "inc-100",
    track_id: "track_1",
    is_escalation: true,
    object_type: "backpack",
    explanation: "High threat: Object unattended for 65.0s",
    evidence: {
      object_type: "backpack",
      dwell_seconds: 65.0,
      person_left_object: true,
      track_id: "track_1",
    }
  }
};

state = updateEventsWithIncoming(state, redEscalation);
assert.strictEqual(state.length, 1, "Escalation must update existing incident in place, NOT create a second incident");
assert.strictEqual(state[0].severity_band, "RED", "Incident severity must be updated to RED");
assert.strictEqual(state[0].threat_score, 70.0, "Incident threat score must be updated to 70.0");
assert.strictEqual(state[0].latest_event_id, "evt-002", "Latest event ID must be recorded");
assert.strictEqual(state[0].payload.explanation, "High threat: Object unattended for 65.0s");

// Test 3: Different track / object -> separate incident
const secondObject = {
  id: "evt-003",
  event_type: "unattended_object",
  severity_band: "YELLOW",
  threat_score: 50.0,
  confidence: 0.82,
  status: "NEW",
  device_id: "device-cctv-01",
  payload: {
    incident_id: "inc-200",
    track_id: "track_2",
    object_type: "suitcase",
    explanation: "Person left suitcase.",
    evidence: {
      object_type: "suitcase",
      dwell_seconds: 5.0,
      person_left_object: true,
      track_id: "track_2",
    }
  }
};

state = updateEventsWithIncoming(state, secondObject);
assert.strictEqual(state.length, 2, "Distinct track/incident must create a separate second incident");
assert.strictEqual(state[0].payload.track_id, "track_2");
assert.strictEqual(state[1].payload.track_id, "track_1");
assert.strictEqual(state[1].severity_band, "RED", "Original incident remains RED");

// Test 4: Historical event consolidation is conservative
const historicalUnrelated = [
  { id: "h-1", event_type: "patrol", severity_band: "GREEN", threat_score: 0, status: "NEW" },
  { id: "h-2", event_type: "patrol", severity_band: "GREEN", threat_score: 0, status: "NEW" },
  { id: "h-3", event_type: "unattended_object", severity_band: "YELLOW", threat_score: 50, status: "NEW", payload: { incident_id: "inc-100" } },
  { id: "h-4", event_type: "unattended_object", severity_band: "RED", threat_score: 70, status: "NEW", payload: { incident_id: "inc-100" } },
];

const consolidated = consolidateHistoricalEvents(historicalUnrelated);
// h-1 and h-2 lack explicit incident_id/track_id -> preserved separately!
// h-3 and h-4 share incident_id "inc-100" -> merged into 1 RED incident
assert.strictEqual(consolidated.length, 3, "Historical consolidation merges only explicit matches and keeps unrelated events separate");
const inc100 = consolidated.find(e => e.payload?.incident_id === "inc-100");
assert.ok(inc100, "inc-100 consolidated");
assert.strictEqual(inc100.severity_band, "RED", "Consolidated to higher RED severity");

console.log("--- All Frontend Incident Regression Tests PASSED Successfully! ---");
