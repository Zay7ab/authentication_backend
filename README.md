# [cite_start]Advanced Asynchronous Backend System (Enterprise Core) [cite: 3]

## Executive Summary
[cite_start]This project is a high-performance, non-blocking asynchronous security and user routing engine[cite: 5]. [cite_start]It is designed to handle concurrent connections efficiently, implement cryptographic token lifecycles, and utilize fast in-memory layers to prevent unauthorized usage without slowing down requests[cite: 6]. [cite_start]The core boundary of this project focuses purely on execution and runtime optimization[cite: 7].

## Core Features
* [cite_start]**Asynchronous Execution Model:** Built entirely on a non-blocking I/O single-thread loop worker model using FastAPI and `asyncpg`[cite: 12].
* [cite_start]**Database Pool Management:** Database engines and fast-storage systems configure state connections using application start/stop lifespans instead of per-request connections[cite: 13].
* [cite_start]**Dual-Token Key Separation:** Authentication uses short-lived Access tokens and long-lived Refresh tokens, signed with completely different cryptographic secrets to prevent unauthorized token extensions[cite: 15, 16].
* **Stateful Token Invalidation (Zero-Trust):** Utilizes a fast memory layer (Redis) to track logouts. [cite_start]When a user logs out, their active token is blacklisted instantly for its remaining valid lifespan[cite: 17, 18].
* [cite_start]**Strict Cryptographic Compliance:** Tokens enforce standard signing algorithms (HS256) and contain explicit structural attributes identifying their exact operational usage[cite: 22].

## Technology Stack
* **Framework:** FastAPI (Python 3.12)
* **Database:** PostgreSQL (via `asyncpg` driver)
* **In-Memory Storage:** Redis (via `redis.asyncio`)
* **Security:** PyJWT, Passlib (bcrypt)
* **CI/CD:** GitHub Actions

## Installation & Local Setup

### 1. Prerequisites
* Python 3.12+
* PostgreSQL running locally or via Docker.
* Redis server running locally or via Docker.

### 2. Clone the Repository
```bash
git clone <your-repository-url>
cd core-auth-system
