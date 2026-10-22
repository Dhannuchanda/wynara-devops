variable "aws_region" {
  type        = string
  description = "AWS region"
}

variable "ami_id" {
  type        = string
  description = "Ubuntu AMI ID for the selected region"
}

variable "instance_type" {
  type        = string
  default     = "t3.micro"
  description = "Small instance type; check current free-tier eligibility"
}

variable "key_name" {
  type        = string
  description = "Existing EC2 key pair name"
}

variable "name" {
  type    = string
  default = "wynara"
}

variable "allowed_ssh_cidrs" {
  type        = list(string)
  description = "Restrict SSH to trusted IP ranges"
}
