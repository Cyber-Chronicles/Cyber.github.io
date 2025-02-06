output "kali_instance_id" {
  value       = aws_instance.kali_instance.id
  description = "Kali Linux instance ID"
}

output "kali_instance_private_ip" {
  value       = aws_instance.kali_instance.private_ip
  description = "Private IP of Kali Linux instance"
}

output "ssm_log_group_name" {
  value       = aws_cloudwatch_log_group.ssm_logs.name
  description = "CloudWatch log group for SSM logs"
}

output "sns_topic_arn" {
  value       = aws_sns_topic.security_alerts.arn
  description = "ARN of security alerts SNS topic"
}

output "vpc_id" {
  value       = module.networking.vpc_resources.vpc_id
  description = "VPC ID for the deployment"
}

output "kali_ssm_role_arn" {
  value       = aws_iam_role.kali_ssm_role.arn
  description = "IAM role ARN for Kali SSM access"
}
