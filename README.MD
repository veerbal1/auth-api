# Auth-API

A production-focused authentication API built with **Rust**, **Axum**, and **Argon2**.

REST API for user registration, login, session management, and logout. Uses Argon2 password hashing and opaque server-side session tokens.

## Stack

**Rust** · **Tokio** · **Axum** · **Argon2** · **Serde** · **Tracing**

## Endpoints

| Method | Path      | Auth   | Description                 |
|--------|-----------|--------|-----------------------------|
| GET    | /         | None   | Root                        |
| GET    | /health   | None   | Process liveness check      |
| POST   | /register | None   | Create user                 |
| POST   | /login    | None   | Authenticate, get token     |
| GET    | /me       | Bearer | Current user info           |
| POST   | /logout   | Bearer | Revoke session              |

## Quick Start

```bash
cargo run
# Server starts at http://127.0.0.1:3000
```

## API Examples

### Health

```bash
curl -s http://127.0.0.1:3000/health | jq
```

### Register

```bash
curl -s -X POST http://127.0.0.1:3000/register \
  -H "Content-Type: application/json" \
  -d '{"email":"alice@example.com","name":"Alice","password":"secret123"}' | jq
```

### Login

```bash
curl -s -X POST http://127.0.0.1:3000/login \
  -H "Content-Type: application/json" \
  -d '{"email":"alice@example.com","password":"secret123"}' | jq
```

### Current User

```bash
curl -s http://127.0.0.1:3000/me \
  -H "Authorization: Bearer <token>" | jq
```

### Logout

```bash
curl -s -X POST http://127.0.0.1:3000/logout \
  -H "Authorization: Bearer <token>" | jq
```

## Features

### Implemented

- Argon2 password hashing
- OsRng session tokens
- Email validation + uniqueness
- Session expiry
- Tracing with `#[instrument]` spans
- No secret leakage in logs
- Uniform login errors

### Pending

- Config from environment variables
- PostgreSQL schema, migrations, and SQLx integration
- Database-backed users and sessions (persist across restarts)
- Unit, integration, and database-backed integration tests
- Docker Compose (Postgres + API) and Dockerfile
- OpenAPI contract documentation

## Architecture

```
src/
├── main.rs       # Router setup
├── handlers.rs   # Request handlers
├── domain.rs     # Core types & logic
└── state.rs      # App state (Arc<Mutex>)
```

## Design Decisions

- **Opaque sessions over JWT** — server-side revocation without complex blocklists; avoids token bloat and clock-skew issues
- **Argon2 over bcrypt/scrypt** — memory-hard, resistant to GPU/ASIC attacks
- **Uniform login errors** — prevents user enumeration

## Running Tests

```bash
cargo test
cargo clippy -- -D warnings
```