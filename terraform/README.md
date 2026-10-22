# Optional Terraform AWS example

This directory is optional and is not used by the VirtualBox deployment. It
provides an example AWS EC2 deployment and never applies infrastructure
automatically.

Before use, install Terraform, configure AWS credentials, copy
`terraform.tfvars.example` to `terraform.tfvars`, and review the plan:

```bash
terraform init
terraform fmt -check
terraform validate
terraform plan -out=tfplan
terraform apply tfplan
```

Use remote state in an S3 bucket with locking before using this beyond a demo.
Never commit `terraform.tfvars`, state files, or private keys.
