terraform {
  required_version = ">= 1.5.0"
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
  }
}

variable "aws_region" {
  type        = string
  default     = "us-east-1"
  description = "AWS Region for deployment"
}

variable "instance_type" {
  type        = string
  default     = "t3.xlarge" # CPU default: ~$0.1664/hr. Switch to "g4dn.xlarge" (~$0.526/hr) for GPU
  description = "EC2 instance type (t3.xlarge for cheap CPU, g4dn.xlarge for NVIDIA T4 GPU)"
}

variable "admin_ip" {
  type        = string
  default     = "127.0.0.1/32" # Replace with your public IP CIDR (e.g. 203.0.113.4/32)
  description = "CIDR block allowed to SSH into the instance"
}

provider "aws" {
  region = var.aws_region
}

# -----------------------------------------------------------------------------
# 1. Least-Privilege IAM Instance Profile for Amazon Bedrock
# -----------------------------------------------------------------------------
resource "aws_iam_role" "ec2_bedrock_role" {
  name = "strands-security-agent-ec2-role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Principal = {
          Service = "ec2.amazonaws.com"
        }
        Action = "sts:AssumeRole"
      }
    ]
  })
}

# Attach AWS SSM Managed Policy so SSH isn't strictly required (Session Manager access)
resource "aws_iam_role_policy_attachment" "ssm_core" {
  role       = aws_iam_role.ec2_bedrock_role.name
  policy_arn = "arn:aws:iam::aws:policy/AmazonSSMManagedInstanceCore"
}

# Strictly scoped inline policy for Bedrock invocation ONLY
resource "aws_iam_role_policy" "bedrock_access" {
  name = "bedrock-invoke-least-privilege"
  role = aws_iam_role.ec2_bedrock_role.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "AllowBedrockFoundationModelInvocation"
        Effect = "Allow"
        Action = [
          "bedrock:InvokeModel",
          "bedrock:InvokeModelWithResponseStream"
        ]
        Resource = [
          "arn:aws:bedrock:*::foundation-model/amazon.nova-micro-v1:0",
          "arn:aws:bedrock:*::foundation-model/amazon.nova-pro-v1:0",
          "arn:aws:bedrock:*::foundation-model/anthropic.claude-sonnet-4-5-20250929-v1:0",
          "arn:aws:bedrock:*:*:inference-profile/us.anthropic.claude-sonnet-4-5-20250929-v1:0",
          "arn:aws:bedrock:*:*:inference-profile/us.amazon.nova-micro-v1:0",
          "arn:aws:bedrock:*:*:inference-profile/us.amazon.nova-pro-v1:0"
        ]
      }
    ]
  })
}

resource "aws_iam_instance_profile" "ec2_profile" {
  name = "strands-security-agent-profile"
  role = aws_iam_role.ec2_bedrock_role.name
}

# -----------------------------------------------------------------------------
# 2. Hardened Security Group
# -----------------------------------------------------------------------------
resource "aws_security_group" "agent_sg" {
  name        = "strands-agent-sg"
  description = "Security group for Strands Decider agent & dashboard"

  # Public HTTPS (Terminated by Reverse Proxy / ALB)
  ingress {
    description = "HTTPS access via Reverse Proxy"
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  # Public HTTP (for Let's Encrypt TLS challenge & HTTP->HTTPS redirection)
  ingress {
    description = "HTTP challenge & redirect"
    from_port   = 80
    to_port     = 80
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  # SSH strictly restricted to administrator CIDR (never 0.0.0.0/0)
  ingress {
    description = "SSH admin access"
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = [var.admin_ip]
  }

  # NOTE: Port 8501 and Port 8099 are STRICTLY CLOSED externally.
  # Traffic reaches Streamlit only via the reverse proxy (Caddy/ALB) on port 443/80.

  egress {
    description = "Outbound internet access for OSINT, NVD, and Bedrock API calls"
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }
}

# -----------------------------------------------------------------------------
# 3. Amazon Linux 2023 EC2 Instance
# -----------------------------------------------------------------------------
data "aws_ami" "al2023" {
  most_recent = true
  owners      = ["amazon"]

  filter {
    name   = "name"
    values = ["al2023-ami-2023.*-x86_64"]
  }
}

resource "aws_instance" "app_host" {
  ami                  = data.aws_ami.al2023.id
  instance_type        = var.instance_type
  iam_instance_profile = aws_iam_instance_profile.ec2_profile.name
  vpc_security_group_ids = [aws_security_group.agent_sg.id]

  root_block_device {
    volume_size           = 40 # 40 GB standard gp3 for Docker images + 4GB model cache
    volume_type           = "gp3"
    delete_on_termination = true
  }

  user_data = <<-EOF
              #!/bin/bash
              dnf update -y
              dnf install -y git
              EOF

  tags = {
    Name    = "Strands-Decider-Security-Agent"
    Project = "Strands-Decider-Hackathon"
  }
}

output "instance_public_ip" {
  value       = aws_instance.app_host.public_ip
  description = "Public IP address of the deployed EC2 instance"
}

output "dashboard_url" {
  value       = "http://${aws_instance.app_host.public_ip}"
  description = "Dashboard link via reverse proxy (Port 80/443)"
}
