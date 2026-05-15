# Advanced Asynchronous Backend System (Enterprise Core)

## Executive Summary
This project is a high-performance, non-blocking asynchronous security and user routing engine[cite: 5]. [cite_start]It is designed to handle concurrent connections efficiently, implement cryptographic token lifecycles, and utilize fast in-memory layers to prevent unauthorized usage without slowing down requests[cite: 6]. [cite_start]The core boundary of this project focuses purely on execution and runtime optimization.

## Core Features
* **Asynchronous Execution Model:** Built entirely on a non-blocking I/O single-thread loop worker model using FastAPI and `asyncpg`[cite: 12].
* **Database Pool Management:** Database engines and fast-storage systems configure state connections using application start/stop lifespans instead of per-request connections.
* **Dual-Token Key Separation:** Authentication uses short-lived Access tokens and long-lived Refresh tokens, signed with completely different cryptographic secrets to prevent unauthorized token extensions.
* **Stateful Token Invalidation (Zero-Trust):** Utilizes a fast memory layer (Redis) to track logouts. [cite_start]When a user logs out, their active token is blacklisted instantly for its remaining valid lifespan.
* **Strict Cryptographic Compliance:** Tokens enforce standard signing algorithms (HS256) and contain explicit structural attributes identifying their exact operational usage.

## Technology Stack
* **Framework:** FastAPI (Python 3.12)
* **Database:** PostgreSQL (via `asyncpg` driver)
* **In-Memory Storage:** Redis (via `redis.asyncio`)
* **Security:** PyJWT, Passlib (bcrypt)
* **CI/CD:** GitHub Actions

## Installation & Local Setup

### Prerequisites
* Python 3.12+
* PostgreSQL running locally or via Docker.
* Redis server running locally or via Docker.

