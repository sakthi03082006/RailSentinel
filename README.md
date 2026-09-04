# RailSentinel

## AI-Powered Railway Security & Threat Response

RailSentinel is an offline-first railway security platform designed to assist Railway Protection Force (RPF) personnel with field-level threat screening, contextual risk assessment, mobile patrol monitoring, secure incident logging, and centralized security visualization.

The platform combines:

- AI-assisted threat screening
- Handheld field-security interface
- Mobile patrol platform simulation
- Offline event storage and synchronization
- Contextual threat scoring
- Secure event and audit logging
- Centralized real-time security dashboard

> **Prototype status:** RailSentinel is an SIH 2026 software prototype. Current AI inference and patrol behavior are simulated/deterministic for demonstrating the complete security workflow. The architecture is designed so trained computer-vision models and physical hardware can be integrated without redesigning the backend, synchronization, or dashboard layers.

---

## 1. Problem

Railway security personnel operate across stations, platforms, yards, tunnels, underframe areas, and other locations where continuous centralized connectivity and fixed surveillance coverage may not always be sufficient.

RailSentinel addresses the field-response gap by providing:

- Rapid identification of suspicious situations
- Context-aware threat prioritization
- Local operation during network outages
- Mobile inspection capability
- Reliable incident recording
- Synchronization after connectivity is restored
- A common operational view for security teams

RailSentinel is designed as a **field-response and threat-coordination layer** that complements existing railway surveillance infrastructure.

---

## 2. Proposed Solution

```text
                ┌──────────────────────────┐
                │   Central Dashboard      │
                │ React + TypeScript       │
                └────────────┬─────────────┘
                             │
                       REST / WebSocket
                             │
                ┌────────────▼─────────────┐
                │     FastAPI Backend      │
                │ Auth / Events / Audit    │
                └────────────┬─────────────┘
                             │
                       PostgreSQL
                             │
          ┌──────────────────┼──────────────────┐
          │                  │                  │
          ▼                  ▼                  ▼
      AI Engine         Edge Agent        Patrol Platform
   Threat Analysis    Offline Queue       Patrol Simulation
````

The system follows a **human-in-the-loop** security workflow.

AI produces evidence and a contextual risk score. Authorized personnel make the final verification and intervention decision.

---

## 3. Core Features

### 3.1 AI-Assisted Threat Screening

The AI layer converts detection evidence into contextual threat analysis.

The current prototype uses deterministic simulation to demonstrate the complete pipeline.

Example evidence:

```text
Object detected
Person leaves object
Object remains stationary
Long dwell duration
High detection confidence
```

The Threat Context Engine converts these signals into a prototype threat score.

### Prototype Threat Bands

|  Score | Level  |
| -----: | ------ |
|   0–30 | GREEN  |
|  31–60 | YELLOW |
| 61–100 | RED    |

These thresholds are **prototype decision bands**, not scientifically validated operational thresholds.

---

### 3.2 Contextual Threat Scoring

RailSentinel does not treat every unattended object as an equal threat.

The scoring layer considers contextual evidence such as:

* Detection confidence
* Object category
* Person-object relationship
* Person leaving an object
* Dwell duration
* Location/context
* Multiple evidence signals

Example:

```text
Detection confidence: 90%
Person left object: YES
Object dwell time: 95 seconds

Threat score: 70
Severity: RED
```

The dashboard receives both the score and an explanation of why the event was prioritized.

---

## 4. Scientific Boundary

RailSentinel does **not** claim that an RGB or thermal camera can directly determine that a closed bag contains explosives or narcotics.

The current system performs:

```text
Visual / contextual evidence
          ↓
AI-assisted analysis
          ↓
Threat context scoring
          ↓
Human verification
```

The system is intended to **assist security personnel**, not replace authorized inspection procedures.

Future trained models may improve object detection, tracking, anomaly detection, and scene understanding.

---

## 5. Offline-First Architecture

Railway field environments can experience unreliable connectivity.

RailSentinel therefore supports local operation through an edge event queue.

```text
          NO NETWORK
              │
              ▼
     ┌─────────────────┐
     │ Local AI/Event  │
     │ Processing      │
     └────────┬────────┘
              │
              ▼
     ┌─────────────────┐
     │ SQLite Outbox   │
     │ QUEUED          │
     └────────┬────────┘
              │
         Network returns
              │
              ▼
     ┌─────────────────┐
     │ Retry / Sync    │
     └────────┬────────┘
              │
              ▼
     ┌─────────────────┐
     │ FastAPI Server  │
     └─────────────────┘
```

Events remain locally stored when the network is unavailable.

When connectivity returns, the synchronization worker retries delivery.

The same event ID is preserved across retries to support idempotent synchronization.

### Current Prototype Capabilities

* Local event creation
* SQLite event/outbox storage
* Offline queue
* Retry handling
* Exponential backoff
* Synchronization after recovery
* Backend-side authoritative event-chain metadata

---

## 6. Mobile Patrol Platform

RailSentinel includes a software representation of a mobile patrol unit.

The architecture is designed for future field platforms such as:

* Wheeled patrol robot
* Quadruped platform
* Underframe inspection platform
* Yard patrol system

The current prototype uses a deterministic patrol simulation.

Example patrol flow:

```text
Patrol starts
     ↓
Routine observation
     ↓
Suspicious object detected
     ↓
Threat score generated
     ↓
RED alert created
     ↓
Event queued/synchronized
     ↓
Dashboard updated
```

The patrol simulator generates location-aware security events without requiring physical robot hardware.

---

## 7. Security & Auditability

RailSentinel includes security mechanisms intended for a prototype security-event pipeline.

### Authentication

* JWT-based authentication
* Role-based access concepts
* Device identity
* Authorized API access

### Event Integrity

Events are linked using a cryptographic hash chain.

```text
Event 1
   │
   ├── hash
   ▼
Event 2
   │
   ├── hash + previous hash
   ▼
Event 3
   │
   ├── hash + previous hash
   ▼
Event 4
```

This allows the system to detect modification or removal of events within the maintained chain.

> SHA-256 is used as a hashing mechanism, not as encryption. The hash chain provides tamper-evidence; it does not by itself make a system immutable.

---

## 8. Central Dashboard

The React dashboard provides an operational security view.

The current interface includes:

* RailSentinel command-center branding
* System status
* Red-event counter
* New-alert counter
* Active-device counter
* Total-event counter
* Security map
* Patrol location
* Threat location
* Live threat feed
* Selected incident details
* Threat score
* Severity
* Event explanation
* Device information

The dashboard communicates with the FastAPI backend through REST APIs and WebSocket events.

---

## 9. Technology Stack

### Frontend

* React
* TypeScript
* Vite
* CSS

### Backend

* Python
* FastAPI
* Pydantic
* JWT authentication
* WebSockets

### Database

* PostgreSQL
* SQLite for edge/offline outbox

### AI

* Python
* Pydantic
* Rule-based contextual scoring
* Deterministic inference simulator
* YOLO-family integration planned

### Edge

* Python
* SQLite
* Offline event queue
* Retry/synchronization worker

### Hardware Simulation

* Python
* Patrol route simulation
* GPS event simulation

### Infrastructure

* Docker
* Docker Compose
* Git
* GitHub

---

## 10. Project Structure

```text
RailSentinel/
│
├── frontend/
│   ├── src/
│   ├── package.json
│   └── vite.config.ts
│
├── backend/
│   ├── app/
│   ├── tests/
│   └── requirements.txt
│
├── ai/
│   └── inference/
│       ├── models.py
│       ├── scoring.py
│       ├── simulator.py
│       ├── integration.py
│       ├── demo.py
│       └── tests/
│
├── edge/
│   ├── app/
│   │   ├── db.py
│   │   ├── schemas.py
│   │   └── sync.py
│   ├── demo_offline.py
│   └── tests/
│
├── hardware/
│   ├── patrol_sim.py
│   ├── demo_hybrid.py
│   ├── tests/
│   └── README.md
│
├── comms/
│   └── Communication layer / planned device interfaces
│
├── docs/
│   └── Project documentation
│
├── docker-compose.yml
├── .env.example
├── .gitignore
└── README.md
```

---

## 11. Requirements

Recommended environment:

* Windows / Linux / macOS
* Git
* Python 3.12+
* Node.js 20+
* npm
* Docker Desktop

Check installations:

```powershell
git --version
python --version
node --version
npm --version
docker --version
```

---

## 12. Clone the Repository

```powershell
git clone https://github.com/sakthi03082006/RailSentinel.git
cd RailSentinel
```

---

## 13. Start Backend and PostgreSQL

From the project root:

```powershell
docker compose up -d
```

Check containers:

```powershell
docker compose ps
```

The FastAPI backend should be available at:

```text
http://localhost:8000
```

API documentation:

```text
http://localhost:8000/docs
```

---

## 14. Start the Frontend

Open another PowerShell window:

```powershell
cd RailSentinel\frontend
npm install
npm run dev
```

Then open the Vite URL shown in the terminal.

Typically:

```text
http://localhost:5173
```

---

## 15. Run the AI Demo

From the project root:

```powershell
python ai/inference/demo.py
```

The demo creates a deterministic high-risk security event and sends it to the backend.

Example:

```text
Severity: RED
Threat Score: 70
```

The resulting event can then appear in the dashboard.

---

## 16. Run the Offline Demo

From the project root:

```powershell
python edge/demo_offline.py
```

The demo demonstrates:

```text
Online
   ↓
Event created
   ↓
Network unavailable
   ↓
Event stored locally
   ↓
RETRY_WAIT
   ↓
Network restored
   ↓
Synchronization
   ↓
SYNCED
```

The original event ID is preserved across retries.

---

## 17. Run the Patrol Demo

From the project root:

```powershell
python hardware/demo_hybrid.py
```

The patrol simulation demonstrates:

* Patrol movement
* Simulated GPS coordinates
* Routine observations
* Suspicious-object observation
* Threat scoring
* Offline queueing
* Event synchronization

Example:

```text
Routine event
     ↓
Suspicious event
     ↓
RED threat
     ↓
Offline queue
     ↓
Network recovery
     ↓
Backend synchronization
```

---

## 18. Run Tests

Run the major prototype test suites:

```powershell
pytest hardware/tests/ edge/tests/ ai/inference/tests/
```

The tests cover areas including:

* Threat scoring
* AI integration
* Event creation
* Offline queue behavior
* Synchronization
* Patrol simulation

---

## 19. Demonstration Scenario

The recommended SIH demonstration flow is:

### Step 1 — Normal Patrol

A patrol unit reports a routine observation.

```text
Threat Score: 0
Severity: GREEN
```

### Step 2 — Suspicious Object

The AI pipeline receives evidence that:

```text
Object detected
Person leaves object
Long dwell time
High detection confidence
```

### Step 3 — Threat Analysis

The Threat Context Engine generates:

```text
Threat Score: 70
Severity: RED
```

### Step 4 — Offline Condition

Network connectivity is intentionally unavailable.

The edge system stores the event locally:

```text
QUEUED
```

### Step 5 — Connectivity Restored

The synchronization worker retries the event:

```text
SYNCING
   ↓
SYNCED
```

### Step 6 — Command Dashboard

The central dashboard displays:

```text
RED ALERT
Threat Score: 70
Location
Device
Event explanation
Timestamp
```

This demonstrates the complete field-to-command-center workflow.

---

## 20. Communication Layer

The architecture is designed to support local device communication in future hardware deployments.

Planned communication technologies include:

* ESP-NOW
* LoRa
* BLE
* Local gateway communication

Communication should be selected according to deployment requirements, range, bandwidth, radio compliance, power consumption, and railway operating constraints.

LoRa is intended for low-bandwidth telemetry and alert messages rather than video transmission.

The current software prototype does not claim completed physical ESP-NOW or LoRa deployment.

---

## 21. Hardware Roadmap

### Handheld Unit

```text
Camera / Sensors
       ↓
Edge processor
       ↓
AI inference
       ↓
Threat scoring
       ↓
Local alert
       ↓
Secure event transmission
```

### Patrol Platform

```text
Camera / Sensors
       ↓
Edge compute
       ↓
Object detection
       ↓
Tracking / context
       ↓
Threat scoring
       ↓
Local storage
       ↓
Wireless synchronization
```

The current SIH prototype focuses on validating the software architecture before integrating physical hardware.

---

## 22. AI Roadmap

### Current

```text
Deterministic inference simulator
        ↓
Contextual threat scoring
        ↓
Backend event
        ↓
Dashboard
```

### Future

```text
Camera
   ↓
YOLO-family object detector
   ↓
Object tracking
   ↓
Behavior/context analysis
   ↓
Threat Context Engine
   ↓
Human verification
```

Potential future model classes include railway-relevant baggage and parcel categories such as:

* Backpacks
* Suitcases
* Travel bags
* Plastic bags
* Jute/bori sacks
* Steel trunks
* Bundles/potlis
* Cardboard parcels

A trained model would require an appropriate railway-domain dataset, validation, evaluation metrics, and operational testing.

---

## 23. Privacy & Responsible AI

RailSentinel follows a human-in-the-loop approach.

The system should:

* Minimize unnecessary personal data
* Avoid treating AI output as proof of wrongdoing
* Provide explainable event evidence
* Allow authorized personnel to make the final decision
* Apply appropriate access controls
* Protect stored event data
* Avoid unnecessary facial recognition or identity processing

AI-generated threat scores are intended for **prioritization and assistance**, not automatic enforcement decisions.

---

## 24. Current Prototype Status

| Component                   | Status             |
| --------------------------- | ------------------ |
| React dashboard             | Implemented        |
| FastAPI backend             | Implemented        |
| PostgreSQL integration      | Implemented        |
| JWT authentication          | Implemented        |
| WebSocket event updates     | Implemented        |
| Threat scoring              | Implemented        |
| AI inference simulator      | Implemented        |
| AI → backend integration    | Implemented        |
| Offline SQLite queue        | Implemented        |
| Retry/synchronization       | Implemented        |
| Patrol simulation           | Implemented        |
| Audit/hash-chain logging    | Implemented        |
| Physical handheld           | Planned            |
| Physical patrol robot       | Planned            |
| ESP-NOW physical networking | Planned            |
| LoRa physical networking    | Planned            |
| Trained YOLO model          | Future integration |
| Railway field validation    | Future work        |

---

## 25. Important Prototype Limitations

RailSentinel is a research/prototype system and should not be interpreted as a certified railway security product.

The current prototype:

* Uses simulated AI inference
* Uses simulated patrol/GPS data
* Does not directly chemically identify explosives or narcotics
* Does not claim RDSO certification
* Does not claim operational railway deployment approval
* Does not replace authorized security inspection
* Requires further testing before real-world deployment

---

## 26. Future Development

Planned improvements include:

1. Train and validate railway-domain object detection models
2. Integrate real camera streams
3. Add multi-object tracking
4. Improve contextual behavior analysis
5. Integrate physical edge hardware
6. Implement ESP-NOW/LoRa device communication
7. Add station-level local gateway
8. Improve device authentication and key management
9. Add richer evidence management
10. Perform field testing and performance evaluation
11. Conduct security testing
12. Evaluate latency, false positives, false negatives, and reliability
13. Integrate with authorized railway security workflows

---

## 27. Why RailSentinel?

RailSentinel focuses on the gap between **detecting a possible threat and responding to it in the field**.

The platform combines:

```text
AI-assisted screening
        +
Contextual risk scoring
        +
Offline-first edge operation
        +
Mobile patrol capability
        +
Secure event logging
        +
Central command dashboard
```

Instead of depending entirely on continuous connectivity or a single surveillance layer, RailSentinel is designed as a distributed security-response platform.

---

## 28. SIH 2026

RailSentinel is being developed as a prototype for **Smart India Hackathon 2026**.

The project demonstrates how AI, edge computing, secure event processing, offline synchronization, and mobile patrol systems can be combined into a railway-security response architecture.

---

## 29. Prototype Disclaimer

This repository contains a research and demonstration prototype.

AI-generated scores and alerts are not validated operational security decisions. Any real railway deployment would require appropriate testing, cybersecurity assessment, hardware validation, regulatory/organizational approvals, privacy safeguards, and integration with authorized railway security procedures.

---

## License

This project is currently intended for academic, research, and SIH demonstration purposes.

````

After replacing the file, run:

```powershell
git add README.md
git commit -m "Rewrite project README"
git push origin main
````
