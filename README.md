# Scalable Identity and Access Management (IAM) Service

A **production-inspired IAM service** built with **Java 21 and Spring Boot 3**, designed to be used as a **drop-in authentication and authorization service** for backend systems.

This project focuses on **correct security primitives**, **explicit token lifecycle management**, and **clean domain-driven structure**.

This is not a demo. It is an IAM system built the way real systems are built.

---

## Why This Project

Authentication systems fail quietly.  
Most examples online cut corners. This one does not.

This service demonstrates:
- Short-lived access tokens
- Stateful refresh tokens with rotation
- OAuth2 login with real providers
- Role and permission based authorization
- Structured authentication audit logging

The intent is to show **security judgment**, not framework usage.

---

## High-Level Architecture

```text
+-------------+        +------------------+
|   Client    | -----> |     Auth API     |
| (Web/Mobile)|        |  Spring Boot     |
+-------------+        +------------------+
                               |
                               v
                  +---------------------------+
                  | Spring Security Filters   |
                  | - JWT Authentication      |
                  | - OAuth2 Login            |
                  +---------------------------+
                               |
                               v
           +-------------------------------------------+
           | Application Layer                         |
           | - AuthService                             |
           | - OAuthLoginService                       |
           | - RefreshTokenService                     |
           | - User & Role Services                    |
           +-------------------------------------------+
                               |
                               v
           +-------------------------------------------+
           | Persistence Layer                         |
           | - PostgreSQL                              |
           | - Users, Roles, Permissions               |
           | - Refresh Tokens                          |
           | - Auth Audit Logs                         |
           +-------------------------------------------+
   ```

---

## Project Structure

The project is organized by **domain**, not by technical layers.  
This keeps security, authorization, and authentication concerns isolated and scalable.

```text
src/main/java/com/jaypal/authapp
├── audit
│   ├── annotation        # Audit annotations
│   ├── application       # Audit service logic
│   ├── aspect            # AOP-based audit interception
│   ├── context           # Audit context propagation
│   ├── domain            # Audit events and enums
│   ├── persistence       # Audit entities and repositories
│   ├── resolver          # Subject and failure resolution
│   └── validation        # Audit validation matrix
│
├── auth
│   ├── api               # Auth REST controllers
│   ├── application       # Authentication services
│   ├── dto               # Request and response models
│   ├── event             # Domain events
│   ├── exception         # Auth-specific exceptions
│   ├── facade            # Web-facing auth orchestration
│   ├── infrastructure    # Cookies, email, token extraction
│   └── listener          # Event listeners
│
├── oauth
│   ├── application       # OAuth login flow
│   ├── dto               # OAuth result models
│   ├── handler           # Success and failure handlers
│   ├── mapper            # Provider-specific user mappers
│   └── model             # Normalized OAuth user model
│
├── security
│   ├── bootstrap         # Permission initialization
│   ├── config            # Security filter chains
│   ├── filter            # JWT authentication filter
│   ├── jwt               # JWT utilities and services
│   ├── principal         # Authenticated principal
│   └── userdetails       # Custom UserDetails service
│
├── token
│   ├── application       # Refresh token lifecycle
│   ├── exception         # Token-related exceptions
│   ├── model             # Refresh token entity
│   └── repository        # Refresh token persistence
│
├── user
│   ├── api               # User and admin controllers
│   ├── application       # User, role, permission services
│   ├── dto               # User and role DTOs
│   ├── exception         # User domain exceptions
│   ├── mapper            # Entity to DTO mapping
│   ├── model             # User, Role, Permission entities
│   └── repository        # User-related repositories
│
├── shared
│   └── exception         # Global and security exceptions
│
└── AuthAppApplication.java

   ```
## Design Choices

- Stateless API  
- Explicit token state  
- Database-backed refresh control  
- No hidden session behavior  

---

## Core Features

### Authentication
- Email and password login  
- OAuth2 login using Google and GitHub  
- BCrypt password hashing  
- Custom user provisioning on first OAuth login  

### Token Management
- JWT access tokens with 15 minute TTL  
- Refresh tokens with 7 day TTL  
- Refresh tokens stored in database  
- Rotation implemented on every refresh  
- Token reuse detection  
- Optimistic locking to prevent race conditions  

### Logout
- Stateless access token handling  
- Explicit refresh token revocation  
- Single session logout  
- Global logout for user or admin actions  

### Authorization
- Role-Based Access Control  
- Explicit User, Role, Permission entities  
- Many-to-many mappings  
- Method-level enforcement using `@PreAuthorize`  
- Central permission bootstrap  

### Audit Logging
- Authentication events persisted as security data  

**Captures**
- Login success and failure  
- Logout  
- Token refresh  

**Includes**
- User ID  
- Provider  
- Failure reason  
- IP address  
- User-Agent  
- Timestamp  

Audit logs are structured. Not log spam.

---

## Technology Stack

- Java 21  
- Spring Boot 3.4.x  
- Spring Security 6.x  
- OAuth2 Client  
- PostgreSQL  
- JPA and Hibernate  
- Maven  
- JWT signed with HS256  
- Stateless API design  

Docker and CI are planned intentionally. Not rushed.

---

## Authentication Flow

### Login
1. User authenticates using credentials or OAuth2  
2. Access token is issued  
3. Refresh token is created and persisted  

### Token Refresh
1. Refresh token is validated  
2. Previous token is revoked  
3. New refresh token is issued  
4. New access token is generated  

### Token Reuse Protection
- Reused or revoked refresh tokens are rejected  
- Race conditions handled via optimistic locking  
- Compromised tokens are invalidated immediately  

This is real refresh token rotation. Not marketing.

---

## OAuth2 Design

- Authorization Code flow  
- Provider-aware user mapping  
- Explicit success and failure handling  
- OAuth treated as authentication input, not identity authority  

### Supported Providers
- Google  
- GitHub  

---

## RBAC Model

### Entities
- User  
- Role  
- Permission  

### Relationships
- User to Role is many-to-many  
- Role to Permission is many-to-many  

### Enforcement
- Method-level security using `@PreAuthorize`  
- No controller-level role hacks  
- Permissions modeled as data  

RBAC is extensible without code rewrites.

---

## Code Organization

Structured by **domain**, not layers.

- `auth` – login, logout, credentials  
- `oauth` – OAuth2 handling  
- `security` – filters and configuration  
- `token` – refresh token lifecycle  
- `user` – users, roles, permissions  
- `audit` – authentication audit logging  

This structure scales. Flat packages do not.

---

## Testing and Documentation Status

- API documentation pending  
- Integration tests pending  

This project prioritized **correct security behavior first**.  
Surface area will be documented after stabilization.

No fake coverage badges.

---

## Engineering Mindset

Built with a QA-driven backend mindset:
- Edge cases modeled explicitly  
- Failure paths treated as first-class  
- Security violations handled deliberately  
- Defensive coding around authentication boundaries  

Security is behavior. Not annotations.

---

## How This Project Should Be Evaluated

### For Large Companies
- Demonstrates understanding of IAM internals  
- Shows token lifecycle reasoning  
- Shows security-first architecture  

### For Startups
- Ready to be extracted as an auth service  
- Clear extension points  
- No unnecessary infrastructure dependencies  

If you want shortcuts, this repository is not for you.

---

## Roadmap

- Dockerization  
- OpenAPI documentation  
- Integration test coverage  
- Redis-backed refresh token optimization  
- CI pipeline  

---

## Final Statement

This project reflects how IAM systems are **designed**, not how tutorials are written.

If you review this code carefully, you will see intent, tradeoffs, and discipline.

That is the signal.

