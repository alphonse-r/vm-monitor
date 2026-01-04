variable "region" {
  description = "AWS region"
  type        = string
  default     = "us-east-1"
}

variable "key_name" {
  description = "Name of the existing AWS key pair"
  type        = string
}

variable "web_instance_count" {
  description = "Number of web target servers"
  type        = number
  default     = 100
}

variable "ami_id" {
  description = "AMI ID for EC2 instances"
  type        = string
}
