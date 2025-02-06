variable "vpc_cidr" {
  type        = string
  description = "CIDR block for the VPC"
  default     = "10.0.0.0/16"
}

variable "availability_zones" {
  type        = list(string)
  description = "List of availability zones to use"
  default     = ["us-east-1a", "us-east-1b"]
}

variable "vpc_endpoints" {
  type        = list(string)
  description = "VPC endpoints to create"
  default     = ["ssm", "ssmmessages", "ec2messages"]
}

variable "kali_instance_type" {
  type        = string
  description = "EC2 instance type for Kali Linux"
  default     = "t3.xlarge"  #t3.2xlarge
}

variable "root_volume_size" {
  type        = number
  description = "Root volume size in GB"
  default     = 50
}

variable "sns_email_endpoint" {
  type        = string
  description = "Email address for security alerts"
  default     = null
}

variable "additional_security_group_rules" {
  type = list(object({
    type        = string
    from_port   = number
    to_port     = number
    protocol    = string
    cidr_blocks = list(string)
  }))
  description = "Additional security group ingress/egress rules"
  default     = []
}
