# Secure Cloud-Native Insurance System (Base Project)

A containerised REST API for managing insurance **policies** and **claims**, built with security and
cloud-native deployment in mind. Stack: Python 3.12, FastAPI, SQLAlchemy, PostgreSQL (SQLite for local dev),
Docker, Kubernetes.

## Features
| Area | Implementation |
|---|---|
| Authentication | JWT bearer tokens (30 min expiry), PBKDF2-SHA256 password hashing (310k iterations) |
| Authorization | Role-based access (customer, agent, adjuster, admin) + object-level checks (customers see only own data) |
| Data protection | Claim descriptions encrypted at rest with Fernet; security headers; strong-password policy |
| Abuse protection | Login lockout after 5 failed attempts, input validation (Pydantic) |
| Auditability | Audit log of logins, policy and claim actions (admin-only endpoint) |
| Cloud-native | 12-factor config via env vars, `/health` probe, non-root Docker image, K8s Deployment/Service/Ingress(TLS)/NetworkPolicy/HPA |
| DevSecOps | GitHub Actions CI: tests, Bandit, pip-audit, Docker build |

## Roles & workflow
1. **Customer** registers, requests a policy (status `pending`).
2. **Agent/Admin** approves it (`active`).
3. **Customer** files a claim on an active policy.
4. **Adjuster/Admin** approves or rejects the claim.
5. **Admin** creates staff accounts and reads the audit log.

## Run locally
```bash
python -m venv .venv && source .venv/bin/activate   # Windows: .venv\Scripts\activate
pip install -r requirements.txt
cp .env.example .env        # then edit secrets
uvicorn app.main:app --reload
```
Open http://localhost:8000/docs for interactive API docs. A default admin is created from `ADMIN_EMAIL` / `ADMIN_PASSWORD`.

## Run tests
```bash
pytest -q
```

## Docker / Compose (with PostgreSQL)
```bash
cp .env.example .env
docker compose up --build
```

## Kubernetes
Build and push the image, set the image name and secrets in `k8s/deployment.yaml`, then:
```bash
kubectl apply -f k8s/deployment.yaml
```

## API summary
| Method | Path | Access |
|---|---|---|
| POST | /auth/register, /auth/login | public |
| GET | /users/me | any user |
| POST | /users | admin |
| POST/GET | /policies, /policies/{id} | customer creates; all read (scoped) |
| POST | /policies/{id}/approve | agent, admin |
| POST | /policies/{id}/cancel | owner, agent, admin |
| POST/GET | /claims | customer files; customer/adjuster/admin read |
| POST | /claims/{id}/review | adjuster, admin |
| GET | /audit | admin |

## Before production
- Generate real `SECRET_KEY` and `DATA_ENCRYPTION_KEY`; store them in a secrets manager (not in git).
- Replace `create_all` with Alembic migrations; use managed PostgreSQL with TLS and encryption at rest.
- Move login-lockout state to Redis for multi-replica deployments; add rate limiting at the gateway.
- Add MFA, refresh-token rotation, centralised logging/monitoring, and a compliance review (GDPR/HIPAA/etc. as applicable).
