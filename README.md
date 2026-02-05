# Flights API — Infrastructure & CI/CD

## What This Deploys

A **Python FastAPI** application (flights CRUD API) containerized with Docker and deployed to **AWS ECS Fargate** behind CloudFront + WAF.

**AWS resources** (all in `main.tf`):

- VPC with 3 public + 3 private subnets across AZs
- Internet Gateway, NAT Gateway, route tables
- Application Load Balancer (public) → ECS Fargate (private)
- DocumentDB Multi-AZ (MongoDB-compatible) — the app connects via `MONGO_URI`
- Aurora RDS PostgreSQL Multi-AZ — provisioned per requirements
- ECR repository with lifecycle policy
- CloudFront + AWS WAF (rate limiting, managed rule sets)
- Security groups: ALB → ECS → DocumentDB/Aurora only

**Traffic flow:** `CloudFront (WAF) → ALB (custom header gate) → ECS Fargate (private) → DocumentDB (private)`

---

## Project Structure

```
.
├── main.tf                          # All Terraform resources
├── terraform.tfvars.example         # Example variable values
├── .github/workflows/
│   ├── ci-cd.yml                    # Main CI/CD pipeline
│   └── rollback.yml                 # Manual emergency rollback
├── docker/
│   ├── Dockerfile                   # Python 3.12 + uvicorn
│   └── docker-compose.yml           # Local dev (app + local Mongo)
├── api/                             # FastAPI application source
│   ├── main.py                      # App entrypoint (health: GET /)
│   ├── settings.py                  # MONGO_URI + MONGO_DB_NAME config
│   ├── mongo.py                     # PyMongo client helpers
│   ├── dependencies.py              # FastAPI DI wiring
│   ├── flights/
│   │   ├── router.py                # GET/POST /flights
│   │   ├── service.py               # Business logic
│   │   └── models.py                # Pydantic models
│   └── tests/
│       ├── test_flights.py          # Flight CRUD tests (mongomock)
│       └── test_liveness.py         # Health check test
├── requirements.txt
├── .gitignore
└── README.md
```

---

## GitHub Secrets (Required)

| Secret | Description |
|---|---|
| `AWS_ACCESS_KEY_ID` | IAM access key |
| `AWS_SECRET_ACCESS_KEY` | IAM secret key |
| `AWS_REGION` | e.g. `us-east-1` |
| `AWS_ACCOUNT_ID` | 12-digit account ID |
| `DB_USERNAME` | Aurora RDS master username |
| `DB_PASSWORD` | Aurora RDS master password (min 8 chars) |
| `DOCDB_USERNAME` | DocumentDB master username |
| `DOCDB_PASSWORD` | DocumentDB master password (min 8 chars) |
| `TF_STATE_BUCKET` | S3 bucket for Terraform state |
| `TF_LOCK_TABLE` | DynamoDB table for state locking |

---

## Application Environment Variables

The app (via `api/settings.py`) requires exactly two env vars:

| Variable | Description | Set by |
|---|---|---|
| `MONGO_URI` | MongoDB connection string | Terraform → ECS task definition (points to DocumentDB) |
| `MONGO_DB_NAME` | Database name (`flights`) | Terraform → ECS task definition |

In the ECS task definition, Terraform injects the DocumentDB endpoint into `MONGO_URI` automatically. The Aurora RDS endpoint is also injected as `DATABASE_URL` for future use.

---

## CI/CD Pipeline

### Push to `main` (full deploy):

```
pytest → terraform validate → terraform plan → docker build → terraform apply → ECS deploy
```

### PR to `main` (validation only):

```
pytest → terraform validate → terraform plan → plan posted as PR comment
```

If **pytest** or **terraform validate/plan** fails, the pipeline stops immediately — no build, no deploy.

### Rollback

**Primary (branch-based):** `git revert HEAD && git push origin main` — pipeline redeploys the previous state.

**Emergency:** Actions → Rollback Deployment → Run workflow → enter the image tag (git SHA) + type `ROLLBACK`.

---

## Usage

### Prerequisites

- Terraform >= 1.6, AWS CLI >= 2.x, Docker >= 24.x, Python 3.12

### 1. Bootstrap Terraform Backend

```bash
aws s3 mb s3://my-tf-state-bucket --region us-east-1
aws dynamodb create-table \
  --table-name terraform-lock \
  --attribute-definitions AttributeName=LockID,AttributeType=S \
  --key-schema AttributeName=LockID,KeyType=HASH \
  --billing-mode PAY_PER_REQUEST
```

### 2. Local Development

```bash
cd docker
docker-compose up --build
# API: http://localhost:8000
# Health: GET /         → 204
# Flights: GET/POST /flights
```

### 3. Deploy Manually (optional)

```bash
terraform init \
  -backend-config="bucket=my-tf-state-bucket" \
  -backend-config="key=flights-api/prod/terraform.tfstate" \
  -backend-config="region=us-east-1" \
  -backend-config="dynamodb_table=terraform-lock" \
  -backend-config="encrypt=true"

terraform validate
terraform plan \
  -var="db_username=admin" -var="db_password=CHANGE_ME" \
  -var="docdb_username=mongoadmin" -var="docdb_password=CHANGE_ME"
terraform apply
```

### 4. Automated (GitHub Actions)

Push to `main` or open a PR. The pipeline runs tests, validates infra, and deploys automatically.

---

## Security (Bonus)

- **CloudFront + WAF:** rate limit 2000 req/5min/IP, AWS Common Rules, Known Bad Inputs
- **ALB gating:** returns 403 unless CloudFront custom header (`X-CF-Secret`) is present — blocks direct ALB access
- **Network isolation:** ECS + databases in private subnets only, NAT for outbound
- **SG least-privilege:** ALB→ECS (port 8000), ECS→DocDB (27017), ECS→Aurora (5432)
- **Encryption:** storage at rest for Aurora + DocumentDB, TLS in transit

---

## Idempotency

All resources are declarative Terraform. Running `terraform apply` with the same inputs produces zero changes. The ECS service uses `ignore_changes = [desired_count, task_definition]` so CI-driven deploys don't cause drift.

---

## Dependencies

| Dependency | Version | Purpose |
|---|---|---|
| hashicorp/aws | ~> 5.0 | AWS provider |
| Terraform | >= 1.6 | IaC engine |
| Python | 3.12 | App runtime |
| FastAPI | 0.112.2 | Web framework |
| pymongo | 4.8.0 | MongoDB driver |
| mongomock | 4.1.2 | Test mock DB |
| Docker | >= 24.0 | Containerization |
