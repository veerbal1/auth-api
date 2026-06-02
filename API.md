# auth-api

Base URL: `http://localhost:3000`

## Endpoints

| Method | Path | Auth | Body | Status | Response |
|--------|------|------|------|--------|----------|
| GET | `/health` | No | — | 200/503 | `{"service","status","database"}` |
| POST | `/register` | No | `{"email","name","password"}` | 201/400/409 | `{"status","message"}` |
| POST | `/login` | No | `{"email","password"}` | 200/401 | `{"status","message","token"}` |
| GET | `/me` | Bearer | — | 200/401 | `{"status","message","user"}` |
| POST | `/logout` | Bearer | — | 200/401 | `{"status","message"}` |
| GET | `/user/{email}` | No | — | 200/404 | `{"email","name"}` |