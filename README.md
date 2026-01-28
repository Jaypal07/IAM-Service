# Scalable Identity and Access Management (IAM) Service  
**Production-Grade IAM Platform | Spring Boot | Security | Fail-Fast Engineering**  

I built this project as part of my transition from **QA to Java backend engineering**.  
It reflects how I think about systems: **break early, fail fast, validate aggressively, and secure everything by default**.

This is not a tutorial project.  
It is a **real Identity and Access Management (IAM) service** designed with **production-grade Spring Boot practices**, **security-first architecture**, and **explicit failure handling**.

---

## Why I Built This

Coming from QA, I am naturally focused on **edge cases, failure paths, and correctness under stress**.  
Instead of avoiding failures, I designed this system to:

- Detect invalid states early  
- Fail loudly instead of silently  
- Treat negative scenarios as first-class behavior  
- Enforce invariants across authentication and authorization  
- Prefer correctness over shortcuts  

This project represents how I **test like a QA engineer but build like a backend engineer**.

---

## My Engineering Mindset: Fail Fast, Secure First

In this codebase, I deliberately:

- Fail fast when security invariants break  
- Avoid hidden session behavior  
- Model token lifecycle states explicitly  
- Reject ambiguous authentication outcomes  
- Use defensive exception taxonomy instead of generic errors  
- Design flows that are predictable, testable, and debuggable  

I care more about **correct behavior than passing demos**.

---

## High-Level Architecture

```text
+------------------------+        +---------------------------+
| Client (Web / Mobile)  | -----> | Auth API (Spring Boot)    |
+------------------------+        +---------------------------+
                                           |
                                           v
                         +-------------------------------------+
                         | Spring Security Filter Chain        |
                         | - JWT Authentication Filter         |
                         | - OAuth2 Login                      |
                         | - Rate Limiting Filter              |
                         +-------------------------------------+
                                           |
                                           v
             +---------------------------------------------------+
             | Application & Domain Services                     |
             | - Auth Service                                    |
             | - Token Issuer & Refresh Lifecycle                |
             | - OAuth Login Service                             |
             | - RBAC Authorization                              |
             | - Email Verification & Password Reset             |
             | - Audit Logging & Security Telemetry              |
             +---------------------------------------------------+
                                           |
                                           v
             +---------------------------------------------------+
             | Persistence & Infrastructure Layer               |
             | - PostgreSQL (Users, Roles, Tokens, Audit)        |
             | - Redis (Rate Limits, Cache)                      |
             +---------------------------------------------------+
```

---

## Domain-Driven Folder Structure

I organized the project by **domain instead of technical layers** to keep responsibilities clear and scalable.

```text
src/main/java/com/jaypal/authapp
├── api                    # REST Controllers (Auth, User, Admin)
│   ├── auth
│   ├── user
│   └── admin
│
├── domain                 # Core business domains
│   ├── audit              # Auth audit logs & invariants
│   ├── token              # Refresh token lifecycle & security
│   └── user               # Users, Roles, Permissions
│
├── service                # Authentication & OAuth workflows
│   ├── auth               # Login, logout, refresh, verification
│   ├── oauth              # OAuth federation services
│   └── operations         # Auth orchestration flows
│
├── infrastructure         # External integrations
│   ├── audit              # Audit context & resolution
│   ├── email              # Email delivery & templates
│   ├── oauth              # OAuth provider handlers
│   ├── ratelimit          # Redis-backed rate limiting
│   ├── security           # Filters, JWT, token extraction
│   └── utils              # Cookie & token utilities
│
├── config                 # Security, Redis, Async, Web config
├── mapper                 # DTO and OAuth user mappers
├── dto                    # Request/response models
├── exception              # Defensive exception taxonomy
├── event                  # Domain events
├── listener               # Async event listeners
└── AuthAppApplication.java
```

This structure prevents package sprawl and supports **long-term maintainability**.

---

## What This System Does

### Authentication & Identity
- Email and password login  
- OAuth2 login (Google and GitHub)  
- BCrypt password hashing  
- Email verification workflow  
- Password reset with secure token validation  
- Token introspection API  

---

### Token Lifecycle & Session Security

**Access Tokens**
- JWT signed with HS256  
- 15-minute TTL  
- Stateless validation  

**Refresh Tokens**
- Stored in PostgreSQL  
- Rotated on every refresh  
- Replay and reuse detection  
- Optimistic locking to prevent race conditions  
- Forced logout and token revocation  
- Token hashing to reduce breach impact  

This implements **real refresh token rotation**, not simplified stateless refresh.

---

## Abuse Prevention & Rate Limiting

To prevent real-world attacks, I implemented:

- Redis-backed token bucket rate limiting  
- Brute-force login protection  
- IP and CIDR-based throttling  
- Admin-controlled rate limit rules  
- Metrics tracking for suspicious behavior  

This models how production systems **handle abuse instead of ignoring it**.

---

## Role-Based Access Control (RBAC)

**Entities**
- User  
- Role  
- Permission  

**Capabilities**
- Many-to-many RBAC mapping  
- Permission bootstrap automation  
- Method-level enforcement using `@PreAuthorize`  
- Admin APIs to manage roles and permissions  

RBAC is **data-driven, extensible, and designed for growth**.

---

## Security Audit & Observability

I built a structured **security audit pipeline** that records:

- Login successes and failures  
- OAuth authentication attempts  
- Token refresh and logout events  
- Authorization decisions  
- Failure reasons and severity classification  
- User ID, provider, IP address, User-Agent, and timestamps  

This includes:
- An audit state machine  
- Failure severity scoring  
- Invariant validation  

Audit logs here act as **security evidence**, not debug logs.

---

## Spring Boot Skills I Demonstrate Here

- Custom Spring Security filter chains  
- OAuth2 Authorization Code Flow  
- JWT authentication and validation  
- Redis integration for rate limiting  
- Transactional domain services  
- Event-driven architecture  
- Structured exception handling  
- Async workflows and audit pipelines  
- Clean layered Spring Boot configuration  

This project reflects **real backend engineering, not tutorial-level Spring Boot**.

---

## How My QA Background Strengthens My Backend Work

My QA experience influences how I build systems:

- I think in edge cases first  
- I design for negative paths before happy paths  
- I validate inputs aggressively  
- I expect misuse and abuse  
- I design features that are testable and deterministic  
- I aim for systems that **fail safely instead of failing silently**  

This helps me build **reliable, predictable backend services**.

---

## Running the Project

### Requirements
- Java 21  
- Maven  
- PostgreSQL  
- Redis  

### Setup
```bash
git clone https://github.com/Jaypal07/Scalable-Identity-Access-Management-IAM-Service
cd Scalable-Identity-Access-Management-IAM-Service
mvn clean install
```

### Configure
Edit:
- `application-dev.yml`
- `.env` (Database, Redis, OAuth credentials)

### Run
```bash
mvn spring-boot:run
```

---

## Why I Think This Project Matters

This repository shows that I:

- Build systems with a **fail-fast mindset**  
- Understand **Spring Boot at a real production level**  
- Apply **QA discipline to backend correctness**  
- Think deeply about **security, tokens, and identity flows**  
- Am ready to **transition from QA to Java backend engineering**  

This is not a demo.  
This is me proving **I can build real backend systems**.

---

## Author

**Jaypal**  
QA → Java Backend Engineer  
Spring Boot | Security | Distributed Systems | Fail-Fast Engineering  

GitHub: https://github.com/Jaypal07  
Linkedin: [jaypal-koli](https://www.linkedin.com/in/jaypal-koli/)
