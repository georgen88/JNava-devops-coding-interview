# Infrastructure & CI/CD Pipeline

## What This Deploys

All infrastructure lives in a **single `main.tf`** file. The CI/CD pipeline is defined in `.github/workflows/`.

**AWS Resources created by Terraform:**

- VPC with 3 public subnets + 3 private subnets across AZs
- Internet Gateway, NAT Gateway, route tables
- Application Load Balancer (public subnets)
- ECS Fargate cluster + service (private subnets)
- Aurora RDS PostgreSQL Multi-AZ cluster (private subnets)
- DocumentDB / MongoDB-compatible cluster (private subnets)
- ECR repository with lifecycle policy
- CloudFront distribution + AWS WAF (rate limiting, managed rules)
- Security groups with least-privilege access (ALB→ECS→DBs only)

**Traffic flow:** CloudFront (WAF) → ALB (custom header validation) → ECS Fargate (private) → Aurora RDS / DocumentDB (private)

---

## Project Structure

```
.
├── main.tf                          # All Terraform resources (single file)
├── terraform.tfvars.example         # Example variable values
├── .github/workflows/
│   ├── ci-cd.yml                    # Main CI/CD pipeline
│   └── rollback.yml                 # Manual emergency rollback
├── docker/
│   ├── Dockerfile                   # Multi-stage app build
│   └── docker-compose.yml           # Local dev compose
├── .gitignore
└── README.md
```

---

## GitHub Secrets (Required)

Configure in **GitHub → Settings → Secrets and Variables → Actions**:

| Secret | Description |
|---|---|
| `AWS_ACCESS_KEY_ID` | IAM access key with permissions for ECR, ECS, RDS, VPC, CloudFront, WAF |
| `AWS_SECRET_ACCESS_KEY` | Corresponding IAM secret key |
| `AWS_REGION` | AWS region (e.g. `us-east-1`) |
| `AWS_ACCOUNT_ID` | 12-digit AWS account ID |
| `DB_USERNAME` | Aurora RDS master username |
| `DB_PASSWORD` | Aurora RDS master password |
| `DOCDB_USERNAME` | DocumentDB master username |
| `DOCDB_PASSWORD` | DocumentDB master password |
| `TF_STATE_BUCKET` | S3 bucket name for Terraform remote state |
| `TF_LOCK_TABLE` | DynamoDB table name for state locking |

---

## CI/CD Pipeline Flow

### On Push to `main` (full deploy):

```
terraform validate → terraform plan → docker build+push to ECR → terraform apply → ECS force deploy
```

### On PR to `main` (validation only):

```
terraform validate → terraform plan → plan posted as PR comment
```

Each job depends on the previous one succeeding. If `terraform validate` or `terraform plan` fails, the pipeline stops — no build, no deploy.

### Rollback

**Primary method (branch-based):** `git revert HEAD && git push origin main`. The pipeline re-runs and deploys the previous known-good state.

**Emergency method:** Go to Actions → "Rollback Deployment" → Run workflow → provide the image tag (git SHA) to roll back to and type `ROLLBACK` to confirm.

---

## Usage

### Prerequisites

- Terraform >= 1.6
- AWS CLI >= 2.x
- Docker >= 24.x

### 1. Create the Terraform Backend

```bash
aws s3 mb s3://my-tf-state-bucket --region us-east-1

aws dynamodb create-table \
  --table-name terraform-lock \
  --attribute-definitions AttributeName=LockID,AttributeType=S \
  --key-schema AttributeName=LockID,KeyType=HASH \
  --billing-mode PAY_PER_REQUEST
```

### 2. Deploy Locally (optional)

```bash
terraform init \
  -backend-config="bucket=my-tf-state-bucket" \
  -backend-config="key=myapp/prod/terraform.tfstate" \
  -backend-config="region=us-east-1" \
  -backend-config="dynamodb_table=terraform-lock" \
  -backend-config="encrypt=true"

terraform validate
terraform plan -var="db_username=admin" -var="db_password=CHANGE_ME" \
               -var="docdb_username=mongoadmin" -var="docdb_password=CHANGE_ME"
terraform apply
```

### 3. Local Docker Development

```bash
cd docker
docker-compose up --build
# App at http://localhost:3000, local Mongo at localhost:27017
```

In production the app connects to Aurora RDS and DocumentDB endpoints instead of local containers. The `DATABASE_URL` and `MONGO_URI` env vars in the ECS task definition point to the Terraform-provisioned cluster endpoints.

### 4. Automated via GitHub Actions

Push to `main` or open a PR. The pipeline handles validate → plan → build → apply → deploy automatically.

---

## Security Configuration (Bonus)

**CloudFront + WAF:**
- All traffic enters through CloudFront, which attaches an AWS WAF WebACL
- WAF rules: rate limiting (2000 req/5min per IP), AWS Common Rule Set, Known Bad Inputs
- ALB rejects any request missing the CloudFront custom header (`X-CF-Secret`) — returns 403

**Network isolation:**
- ECS tasks and databases run in private subnets only (no public IPs)
- NAT Gateway provides outbound-only internet for private subnets
- Security groups: ALB → ECS (app port only) → Aurora (5432) / DocumentDB (27017)
- All database storage encrypted at rest, TLS enforced in transit

---

## Idempotency

All resources are fully declarative Terraform. Running `terraform apply` multiple times with the same inputs produces zero changes. The ECS service uses `lifecycle { ignore_changes = [desired_count, task_definition] }` so that CI-driven deployments don't cause Terraform drift.

---

## Dependencies

| Dependency | Version | Purpose |
|---|---|---|
| hashicorp/aws provider | ~> 5.0 | AWS resource management |
| Terraform | >= 1.6 | IaC engine |
| Docker | >= 24.0 | Container builds |
| GitHub Actions | v4 | CI/CD runner |
