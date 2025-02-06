# Get current AWS region and account details
data "aws_region" "current" {}
data "aws_caller_identity" "current" {}

# Create VPC Network
module "networking" {
  source = "./modules/vpc"

  vpc_config = {
    cidr_block           = var.vpc_cidr
    enable_dns_hostnames = true
    enable_dns_support   = true
    availability_zones   = var.availability_zones
    tags = {
      "Name" = "kali-pentesting-vpc"
    }
  }
}

# VPC Endpoints for SSM
resource "aws_vpc_endpoint" "vpc_endpoints" {
  for_each            = toset(var.vpc_endpoints)
  vpc_id              = module.networking.vpc_resources.vpc_id
  subnet_ids          = module.networking.vpc_resources.private_subnet_ids
  service_name        = "com.amazonaws.${data.aws_region.current.name}.${each.key}"
  vpc_endpoint_type   = "Interface"
  private_dns_enabled = true
  security_group_ids  = [aws_security_group.vpce_security_groups.id]
  
  tags = {
    "Name" = "kali-vpc-endpoint-${each.key}"
  }
}

# Kali Linux AMI Datasource
data "aws_ami" "kali_linux" {
  most_recent = true
  owners      = ["679593333241"] # Official Kali Linux AMI owner

  filter {
    name   = "name"
    values = ["kali-linux-*-x86_64-*"]
  }

  filter {
    name   = "root-device-type"
    values = ["ebs"]
  }

  filter {
    name   = "virtualization-type"
    values = ["hvm"]
  }
}

# Kali Instance Resource
resource "aws_instance" "kali_instance" {
  ami                         = data.aws_ami.kali_linux.id
  instance_type               = var.kali_instance_type
  subnet_id                   = module.networking.vpc_resources.private_subnet_ids[0]
  vpc_security_group_ids      = [aws_security_group.kali_sg.id]
  iam_instance_profile        = aws_iam_instance_profile.kali_ssm_profile.name
  monitoring                  = true
  
  user_data                   = templatefile("userdata.sh", {
    cloudwatch_log_group = aws_cloudwatch_log_group.ssm_logs.name
  })
  user_data_replace_on_change = true

  root_block_device {
    volume_size = var.root_volume_size
    encrypted   = true
    volume_type = "gp3"
  }

  tags = {
    Name = "Kali-Penetration-Testing-Instance"
    Environment = "Security-Research"
  }
}

# CloudWatch Log Group for SSM Logs
resource "aws_cloudwatch_log_group" "ssm_logs" {
  name              = "/aws/ssm/kali-instance-logs"
  retention_in_days = 30
  kms_key_id        = aws_kms_key.log_encryption_key.arn
}

# SNS Topic for Alerts
resource "aws_sns_topic" "security_alerts" {
  name = "kali-security-alerts"
}

# CloudWatch Metric Filter for Suspicious Commands
resource "aws_cloudwatch_log_metric_filter" "suspicious_commands" {
  name           = "suspicious-command-filter"
  pattern        = "/(whoami|cat /etc/passwd|cat /etc/shadow|sudo)/"
  log_group_name = aws_cloudwatch_log_group.ssm_logs.name

  metric_transformation {
    name      = "SuspiciousCommandCount"
    namespace = "SecurityMetrics"
    value     = "1"
  }
}
