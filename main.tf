###############################################################################
# main.tf — Complete AWS Infrastructure (single file)
#
# Resources:
#   - VPC: 3 public + 3 private subnets across AZs
#   - Internet Gateway, NAT Gateway, route tables
#   - Application Load Balancer (public subnets) → ECS (private subnets)
#   - ECS Fargate: Python FastAPI app container
#   - DocumentDB (MongoDB-compatible) Multi-AZ — app connects via MONGO_URI
#   - Aurora RDS PostgreSQL Multi-AZ — provisioned per requirements
#   - ECR repository for Docker images
#   - CloudFront + WAF: rate limiting, AWS managed rule sets
#   - Security groups: least-privilege (ALB→ECS→DBs only)
#
# The app uses two env vars: MONGO_URI and MONGO_DB_NAME
# DocumentDB endpoint is injected into the ECS task definition automatically.
###############################################################################

# ─── Providers & Backend ─────────────────────────────────────────────────────

terraform {
  required_version = ">= 1.6.0"

  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
  }

  #backend "s3" {}
}

provider "aws" {
  region = var.aws_region

  default_tags {
    tags = {
      Project     = var.app_name
      Environment = var.environment
      ManagedBy   = "terraform"
    }
  }
}

# ─── Variables ───────────────────────────────────────────────────────────────

variable "aws_region" {
  description = "AWS region"
  type        = string
  default     = "us-east-1"
}

variable "app_name" {
  description = "Application name prefix"
  type        = string
  default     = "flights-api"
}

variable "environment" {
  description = "Deployment environment"
  type        = string
  default     = "prod"
}

variable "vpc_cidr" {
  description = "VPC CIDR block"
  type        = string
  default     = "10.0.0.0/16"
}

variable "app_port" {
  description = "Port the FastAPI app listens on"
  type        = number
  default     = 8000
}

variable "app_image" {
  description = "Full ECR image URI:tag — set by CI pipeline"
  type        = string
  default     = ""
}

variable "ecs_cpu" {
  description = "Fargate task CPU units"
  type        = number
  default     = 256
}

variable "ecs_memory" {
  description = "Fargate task memory (MiB)"
  type        = number
  default     = 512
}

variable "desired_count" {
  description = "ECS desired task count"
  type        = number
  default     = 2
}

variable "db_username" {
  description = "Aurora RDS master username"
  type        = string
  sensitive   = true
  default     = "flights"

}

variable "db_password" {
  description = "Aurora RDS master password (min 8 chars)"
  type        = string
  sensitive   = true
  default     = "flights"
}

variable "docdb_username" {
  description = "DocumentDB master username"
  type        = string
  sensitive   = true
  default     = "flights"
}

variable "docdb_password" {
  description = "DocumentDB master password (min 8 chars)"
  type        = string
  sensitive   = true
  default     = "flights"
}

variable "mongo_db_name" {
  description = "MongoDB database name used by the app"
  type        = string
  default     = "flights"
}

variable "aurora_instance_class" {
  description = "Aurora RDS instance class"
  type        = string
  default     = "db.r6g.large"
}

variable "docdb_instance_class" {
  description = "DocumentDB instance class"
  type        = string
  default     = "db.r6g.large"
}

# ─── Data Sources & Locals ───────────────────────────────────────────────────

data "aws_availability_zones" "available" {
  state = "available"
}

data "aws_caller_identity" "current" {}

locals {
  prefix = "${var.app_name}-${var.environment}"
  azs    = slice(data.aws_availability_zones.available.names, 0, 3)

  public_cidrs  = ["10.0.1.0/24", "10.0.2.0/24", "10.0.3.0/24"]
  private_cidrs = ["10.0.11.0/24", "10.0.12.0/24", "10.0.13.0/24"]

  cf_header_name  = "X-CF-Secret"
  cf_header_value = "cf-${var.app_name}-${var.environment}-secret"
}

###############################################################################
# VPC + NETWORKING
###############################################################################

resource "aws_vpc" "main" {
  cidr_block           = var.vpc_cidr
  enable_dns_support   = true
  enable_dns_hostnames = true
  tags                 = { Name = "${local.prefix}-vpc" }
}

resource "aws_internet_gateway" "main" {
  vpc_id = aws_vpc.main.id
  tags   = { Name = "${local.prefix}-igw" }
}

# ── Public subnets ───────────────────────────────────────────────────────────

resource "aws_subnet" "public" {
  count                   = 3
  vpc_id                  = aws_vpc.main.id
  cidr_block              = local.public_cidrs[count.index]
  availability_zone       = local.azs[count.index]
  map_public_ip_on_launch = true
  tags                    = { Name = "${local.prefix}-public-${local.azs[count.index]}" }
}

resource "aws_route_table" "public" {
  vpc_id = aws_vpc.main.id
  tags   = { Name = "${local.prefix}-public-rt" }
}

resource "aws_route" "public_igw" {
  route_table_id         = aws_route_table.public.id
  destination_cidr_block = "0.0.0.0/0"
  gateway_id             = aws_internet_gateway.main.id
}

resource "aws_route_table_association" "public" {
  count          = 3
  subnet_id      = aws_subnet.public[count.index].id
  route_table_id = aws_route_table.public.id
}

# ── NAT Gateway ──────────────────────────────────────────────────────────────

resource "aws_eip" "nat" {
  domain = "vpc"
  tags   = { Name = "${local.prefix}-nat-eip" }
}

resource "aws_nat_gateway" "main" {
  allocation_id = aws_eip.nat.id
  subnet_id     = aws_subnet.public[0].id
  tags          = { Name = "${local.prefix}-nat" }
  depends_on    = [aws_internet_gateway.main]
}

# ── Private subnets ──────────────────────────────────────────────────────────

resource "aws_subnet" "private" {
  count             = 3
  vpc_id            = aws_vpc.main.id
  cidr_block        = local.private_cidrs[count.index]
  availability_zone = local.azs[count.index]
  tags              = { Name = "${local.prefix}-private-${local.azs[count.index]}" }
}

resource "aws_route_table" "private" {
  vpc_id = aws_vpc.main.id
  tags   = { Name = "${local.prefix}-private-rt" }
}

resource "aws_route" "private_nat" {
  route_table_id         = aws_route_table.private.id
  destination_cidr_block = "0.0.0.0/0"
  nat_gateway_id         = aws_nat_gateway.main.id
}

resource "aws_route_table_association" "private" {
  count          = 3
  subnet_id      = aws_subnet.private[count.index].id
  route_table_id = aws_route_table.private.id
}

###############################################################################
# SECURITY GROUPS
###############################################################################

resource "aws_security_group" "alb" {
  name_prefix = "${local.prefix}-alb-"
  vpc_id      = aws_vpc.main.id
  description = "ALB - HTTP/HTTPS inbound"

  ingress {
    description = "HTTP"
    from_port   = 80
    to_port     = 80
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  ingress {
    description = "HTTPS"
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  lifecycle { create_before_destroy = true }
  tags = { Name = "${local.prefix}-alb-sg" }
}

resource "aws_security_group" "ecs" {
  name_prefix = "${local.prefix}-ecs-"
  vpc_id      = aws_vpc.main.id
  description = "ECS tasks - inbound from ALB only"

  ingress {
    description     = "App port from ALB"
    from_port       = var.app_port
    to_port         = var.app_port
    protocol        = "tcp"
    security_groups = [aws_security_group.alb.id]
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  lifecycle { create_before_destroy = true }
  tags = { Name = "${local.prefix}-ecs-sg" }
}

resource "aws_security_group" "docdb" {
  name_prefix = "${local.prefix}-docdb-"
  vpc_id      = aws_vpc.main.id
  description = "DocumentDB - inbound from ECS only"

  ingress {
    description     = "MongoDB from ECS"
    from_port       = 27017
    to_port         = 27017
    protocol        = "tcp"
    security_groups = [aws_security_group.ecs.id]
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  lifecycle { create_before_destroy = true }
  tags = { Name = "${local.prefix}-docdb-sg" }
}

resource "aws_security_group" "aurora" {
  name_prefix = "${local.prefix}-aurora-"
  vpc_id      = aws_vpc.main.id
  description = "Aurora RDS - inbound from ECS only"

  ingress {
    description     = "PostgreSQL from ECS"
    from_port       = 5432
    to_port         = 5432
    protocol        = "tcp"
    security_groups = [aws_security_group.ecs.id]
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  lifecycle { create_before_destroy = true }
  tags = { Name = "${local.prefix}-aurora-sg" }
}

###############################################################################
# ECR
###############################################################################

resource "aws_ecr_repository" "app" {
  name                 = var.app_name
  image_tag_mutability = "MUTABLE"
  force_delete         = true

  image_scanning_configuration {
    scan_on_push = true
  }
  tags = { Name = "${local.prefix}-ecr" }
}

resource "aws_ecr_lifecycle_policy" "app" {
  repository = aws_ecr_repository.app.name
  policy = jsonencode({
    rules = [{
      rulePriority = 1
      description  = "Keep last 10 images"
      selection = {
        tagStatus   = "any"
        countType   = "imageCountMoreThan"
        countNumber = 10
      }
      action = { type = "expire" }
    }]
  })
}

###############################################################################
# APPLICATION LOAD BALANCER
###############################################################################

resource "aws_lb" "main" {
  name               = "${local.prefix}-alb"
  internal           = false
  load_balancer_type = "application"
  security_groups    = [aws_security_group.alb.id]
  subnets            = aws_subnet.public[*].id
  tags               = { Name = "${local.prefix}-alb" }
}

resource "aws_lb_target_group" "app" {
  name        = "${local.prefix}-tg"
  port        = var.app_port
  protocol    = "HTTP"
  vpc_id      = aws_vpc.main.id
  target_type = "ip"

  health_check {
    path                = "/"
    protocol            = "HTTP"
    matcher             = "204"
    healthy_threshold   = 2
    unhealthy_threshold = 3
    timeout             = 5
    interval            = 30
  }

  lifecycle { create_before_destroy = true }
  tags = { Name = "${local.prefix}-tg" }
}

# Default: 403 unless CloudFront header present
resource "aws_lb_listener" "http" {
  load_balancer_arn = aws_lb.main.arn
  port              = 80
  protocol          = "HTTP"

  default_action {
    type = "fixed-response"
    fixed_response {
      content_type = "text/plain"
      message_body = "Forbidden"
      status_code  = "403"
    }
  }
}

resource "aws_lb_listener_rule" "cf_forward" {
  listener_arn = aws_lb_listener.http.arn
  priority     = 1

  condition {
    http_header {
      http_header_name = local.cf_header_name
      values           = [local.cf_header_value]
    }
  }

  action {
    type             = "forward"
    target_group_arn = aws_lb_target_group.app.arn
  }
}

###############################################################################
# DOCUMENTDB (MongoDB-compatible) — private subnets, Multi-AZ
###############################################################################

resource "aws_docdb_subnet_group" "main" {
  name       = "${local.prefix}-docdb-subnets"
  subnet_ids = aws_subnet.private[*].id
  tags       = { Name = "${local.prefix}-docdb-subnets" }
}

resource "aws_docdb_cluster" "main" {
  cluster_identifier     = "${local.prefix}-docdb"
  engine                 = "docdb"
  master_username        = var.docdb_username
  master_password        = var.docdb_password
  db_subnet_group_name   = aws_docdb_subnet_group.main.name
  vpc_security_group_ids = [aws_security_group.docdb.id]
  storage_encrypted      = true
  deletion_protection    = false
  skip_final_snapshot    = true
  tags                   = { Name = "${local.prefix}-docdb" }
}

# 2 instances across AZs for Multi-AZ
resource "aws_docdb_cluster_instance" "main" {
  count              = 2
  identifier         = "${local.prefix}-docdb-${count.index}"
  cluster_identifier = aws_docdb_cluster.main.id
  instance_class     = var.docdb_instance_class
  tags               = { Name = "${local.prefix}-docdb-${count.index}" }
}

###############################################################################
# AURORA RDS PostgreSQL — Multi-AZ (per requirements)
###############################################################################

resource "aws_db_subnet_group" "aurora" {
  name       = "${local.prefix}-aurora-subnets"
  subnet_ids = aws_subnet.private[*].id
  tags       = { Name = "${local.prefix}-aurora-subnets" }
}

resource "aws_rds_cluster" "aurora" {
  cluster_identifier     = "${local.prefix}-aurora"
  engine                 = "aurora-postgresql"
  engine_version         = "15.4"
  database_name          = replace(var.app_name, "-", "_")
  master_username        = var.db_username
  master_password        = var.db_password
  db_subnet_group_name   = aws_db_subnet_group.aurora.name
  vpc_security_group_ids = [aws_security_group.aurora.id]
  storage_encrypted      = true
  deletion_protection    = false
  skip_final_snapshot    = true
  tags                   = { Name = "${local.prefix}-aurora" }
}

resource "aws_rds_cluster_instance" "aurora" {
  count              = 2
  identifier         = "${local.prefix}-aurora-${count.index}"
  cluster_identifier = aws_rds_cluster.aurora.id
  instance_class     = var.aurora_instance_class
  engine             = aws_rds_cluster.aurora.engine
  engine_version     = aws_rds_cluster.aurora.engine_version
  tags               = { Name = "${local.prefix}-aurora-${count.index}" }
}

###############################################################################
# ECS FARGATE — FastAPI app on private subnets
###############################################################################

resource "aws_ecs_cluster" "main" {
  name = "${local.prefix}-cluster"
  setting {
    name  = "containerInsights"
    value = "enabled"
  }
  tags = { Name = "${local.prefix}-cluster" }
}

resource "aws_cloudwatch_log_group" "ecs" {
  name              = "/ecs/${local.prefix}"
  retention_in_days = 30
  tags              = { Name = "${local.prefix}-logs" }
}

# IAM — execution role (ECR pull + CloudWatch)
resource "aws_iam_role" "ecs_execution" {
  name = "${local.prefix}-ecs-exec-role"
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Principal = { Service = "ecs-tasks.amazonaws.com" }
      Action    = "sts:AssumeRole"
    }]
  })
  tags = { Name = "${local.prefix}-ecs-exec-role" }
}

resource "aws_iam_role_policy_attachment" "ecs_execution" {
  role       = aws_iam_role.ecs_execution.name
  policy_arn = "arn:aws:iam::aws:policy/service-role/AmazonECSTaskExecutionRolePolicy"
}

# IAM — task role (app-level perms)
resource "aws_iam_role" "ecs_task" {
  name = "${local.prefix}-ecs-task-role"
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Principal = { Service = "ecs-tasks.amazonaws.com" }
      Action    = "sts:AssumeRole"
    }]
  })
  tags = { Name = "${local.prefix}-ecs-task-role" }
}

# Task definition — injects DocumentDB endpoint as MONGO_URI
resource "aws_ecs_task_definition" "app" {
  family                   = "${local.prefix}-task"
  network_mode             = "awsvpc"
  requires_compatibilities = ["FARGATE"]
  cpu                      = var.ecs_cpu
  memory                   = var.ecs_memory
  execution_role_arn       = aws_iam_role.ecs_execution.arn
  task_role_arn            = aws_iam_role.ecs_task.arn

  container_definitions = jsonencode([{
    name      = var.app_name
    image     = var.app_image != "" ? var.app_image : "${aws_ecr_repository.app.repository_url}:latest"
    essential = true

    portMappings = [{
      containerPort = var.app_port
      protocol      = "tcp"
    }]

    environment = [
      {
        name  = "MONGO_URI"
        value = "mongodb://${var.docdb_username}:${var.docdb_password}@${aws_docdb_cluster.main.endpoint}:27017/?tls=true&tlsCAFile=/tmp/rds-combined-ca-bundle.pem&retryWrites=false&directConnection=true"
      },
      {
        name  = "MONGO_DB_NAME"
        value = var.mongo_db_name
      },
      # Aurora RDS endpoint available if app needs a relational DB later
      {
        name  = "DATABASE_URL"
        value = "postgresql://${var.db_username}:${var.db_password}@${aws_rds_cluster.aurora.endpoint}:5432/${replace(var.app_name, "-", "_")}"
      },
    ]

    logConfiguration = {
      logDriver = "awslogs"
      options = {
        "awslogs-group"         = aws_cloudwatch_log_group.ecs.name
        "awslogs-region"        = var.aws_region
        "awslogs-stream-prefix" = "ecs"
      }
    }
  }])

  tags = { Name = "${local.prefix}-task-def" }
}

resource "aws_ecs_service" "app" {
  name            = "${local.prefix}-service"
  cluster         = aws_ecs_cluster.main.id
  task_definition = aws_ecs_task_definition.app.arn
  desired_count   = var.desired_count
  launch_type     = "FARGATE"

  network_configuration {
    subnets          = aws_subnet.private[*].id
    security_groups  = [aws_security_group.ecs.id]
    assign_public_ip = false
  }

  load_balancer {
    target_group_arn = aws_lb_target_group.app.arn
    container_name   = var.app_name
    container_port   = var.app_port
  }

  lifecycle {
    ignore_changes = [desired_count, task_definition]
  }

  depends_on = [aws_lb_listener.http]
  tags       = { Name = "${local.prefix}-service" }
}

###############################################################################
# CLOUDFRONT + WAF (Bonus)
###############################################################################

resource "aws_wafv2_web_acl" "main" {
  name  = "${local.prefix}-waf"
  scope = "CLOUDFRONT"

  default_action {
    allow {}
  }

  # Rate limit: 2000 req / 5 min per IP
  rule {
    name     = "rate-limit"
    priority = 1
    action {
      block {}
    }
    statement {
      rate_based_statement {
        limit              = 2000
        aggregate_key_type = "IP"
      }
    }
    visibility_config {
      sampled_requests_enabled   = true
      cloudwatch_metrics_enabled = true
      metric_name                = "${local.prefix}-rate-limit"
    }
  }

  # AWS managed common rule set
  rule {
    name     = "aws-common-rules"
    priority = 2
    override_action {
      none {}
    }
    statement {
      managed_rule_group_statement {
        vendor_name = "AWS"
        name        = "AWSManagedRulesCommonRuleSet"
      }
    }
    visibility_config {
      sampled_requests_enabled   = true
      cloudwatch_metrics_enabled = true
      metric_name                = "${local.prefix}-common-rules"
    }
  }

  # AWS managed known bad inputs
  rule {
    name     = "aws-bad-inputs"
    priority = 3
    override_action {
      none {}
    }
    statement {
      managed_rule_group_statement {
        vendor_name = "AWS"
        name        = "AWSManagedRulesKnownBadInputsRuleSet"
      }
    }
    visibility_config {
      sampled_requests_enabled   = true
      cloudwatch_metrics_enabled = true
      metric_name                = "${local.prefix}-bad-inputs"
    }
  }

  visibility_config {
    sampled_requests_enabled   = true
    cloudwatch_metrics_enabled = true
    metric_name                = "${local.prefix}-waf"
  }

  tags = { Name = "${local.prefix}-waf" }
}

resource "aws_cloudfront_distribution" "main" {
  enabled         = true
  is_ipv6_enabled = true
  comment         = "${local.prefix} API"
  web_acl_id      = aws_wafv2_web_acl.main.arn

  origin {
    domain_name = aws_lb.main.dns_name
    origin_id   = "alb"

    custom_origin_config {
      http_port              = 80
      https_port             = 443
      origin_protocol_policy = "http-only"
      origin_ssl_protocols   = ["TLSv1.2"]
    }

    custom_header {
      name  = local.cf_header_name
      value = local.cf_header_value
    }
  }

  default_cache_behavior {
    allowed_methods        = ["DELETE", "GET", "HEAD", "OPTIONS", "PATCH", "POST", "PUT"]
    cached_methods         = ["GET", "HEAD"]
    target_origin_id       = "alb"
    viewer_protocol_policy = "redirect-to-https"

    forwarded_values {
      query_string = true
      headers      = ["Host", "Origin", "Authorization"]
      cookies {
        forward = "all"
      }
    }

    min_ttl     = 0
    default_ttl = 0
    max_ttl     = 0
  }

  restrictions {
    geo_restriction {
      restriction_type = "none"
    }
  }

  viewer_certificate {
    cloudfront_default_certificate = true
  }

  tags = { Name = "${local.prefix}-cloudfront" }
}

###############################################################################
# OUTPUTS
###############################################################################

output "vpc_id" {
  value = aws_vpc.main.id
}

output "alb_dns_name" {
  value = aws_lb.main.dns_name
}

output "cloudfront_domain" {
  description = "Public URL — use this to reach the API"
  value       = aws_cloudfront_distribution.main.domain_name
}

output "ecr_repository_url" {
  value = aws_ecr_repository.app.repository_url
}

output "docdb_endpoint" {
  description = "DocumentDB (MongoDB) endpoint for MONGO_URI"
  value       = aws_docdb_cluster.main.endpoint
}

output "aurora_endpoint" {
  description = "Aurora RDS writer endpoint"
  value       = aws_rds_cluster.aurora.endpoint
}

output "aurora_reader_endpoint" {
  value = aws_rds_cluster.aurora.reader_endpoint
}

output "ecs_cluster_name" {
  value = aws_ecs_cluster.main.name
}

output "ecs_service_name" {
  value = aws_ecs_service.app.name
}

