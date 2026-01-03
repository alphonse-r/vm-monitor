provider "aws" {
  region = var.region
}

############################
# Default VPC
############################
data "aws_vpc" "default" {
  default = true
}

############################
# Security Group
############################
resource "aws_security_group" "ec2_sg" {
  name        = "ansible-sg"
  description = "Security group for Ansible master and web targets"
  vpc_id      = data.aws_vpc.default.id

  ingress {
    description = "SSH"
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

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
  
  ingress {
    description = "SMTP"
    from_port   = 587
    to_port     = 587
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }


  ingress {
    description = "Custom ports 9000-30000"
    from_port   = 9000
    to_port     = 30000
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = {
    Name = "ansible-security-group"
  }
}

############################
# Ansible Master
############################
resource "aws_instance" "ansible_master" {
  ami           = var.ami_id
  instance_type = "t2.medium"
  key_name      = var.key_name
  vpc_security_group_ids = [aws_security_group.ec2_sg.id]

  tags = {
    Name = "ansible-master"
  }
}
############################
# Web Target Servers
############################
resource "aws_instance" "web_targets" {
  count                  = var.web_instance_count
  ami                    = var.ami_id
  instance_type          = "t2.small"
  key_name               = var.key_name
  vpc_security_group_ids = [aws_security_group.ec2_sg.id]

  tags = {
    Name        = format("web-%02d", count.index + 1)
    Environment = "dev"
  }
}
