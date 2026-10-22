# Wynara DevOps Portfolio Project

Wynara is a Flask application that manages student identities, certificates,
HR recruitment workflows, and administrative operations. This repository wraps
the existing server-rendered Flask application in a reproducible DevOps
delivery path: Docker, Nginx HTTPS, GitHub Actions, GHCR, Ansible, optional
Terraform, Prometheus, and Grafana.

## Architecture

```mermaid
flowchart LR
    Dev[Developer] --> GitHub[GitHub repository]
    GitHub --> Actions[GitHub Actions]
    Actions --> Tests[Pytest and Ruff]
    Actions --> Scan[Buildx and Trivy]
    Actions --> GHCR[GHCR image registry]
    GHCR --> Runner[Self-hosted runner on Ubuntu VM]
    Runner --> Nginx[Nginx HTTPS reverse proxy]
    Nginx --> Flask[Flask and Gunicorn]
    Flask --> SQLite[(SQLite volume)]
    Flask --> Uploads[(Upload volumes)]
    Flask --> Metrics[/metrics]
    Metrics --> Prometheus[Prometheus]
    Prometheus --> Grafana[Grafana dashboard]
    VM[Ubuntu host] --> Node[node-exporter]
    VM --> CAdvisor[cAdvisor]
    Node --> Prometheus
    CAdvisor --> Prometheus
```

Nginx is the only publicly exposed container. Flask listens on the internal
Compose network, and `/metrics` is intentionally not exposed through Nginx.

## Application stack

- Python 3.12 runtime image
- Flask 3.0 with Jinja templates and static files
- Gunicorn WSGI server
- SQLite by default, with PostgreSQL support through `DATABASE_URL`
- Named Docker volumes for SQLite runtime data and uploads
- Gmail/Resend integrations for OTP delivery
- Razorpay integration for payments

## Repository layout

```text
.
├── app.py
├── wsgi.py
├── config.py
├── database.py
├── routes/
├── templates/
├── static/
├── Dockerfile
├── docker-compose.yml
├── docker-compose.monitoring.yml
├── nginx/
├── scripts/
├── tests/
├── monitoring/
├── ansible/
├── terraform/
└── .github/workflows/
```

## Prerequisites

### Windows development

- Git
- Python 3.12+
- VS Code
- PowerShell
- Optional Docker Desktop for local container testing

### Ubuntu VM deployment

- Ubuntu 26.04.1 LTS VM
- Docker Engine
- Docker Compose plugin
- `curl`, `openssl`, and Git
- Network access to GitHub and GHCR
- A self-hosted GitHub Actions runner

## Local development on Windows

```powershell
git clone https://github.com/Dhannuchanda/WAPL_Dhannu_3-2-26.git
Set-Location WAPL_Dhannu_3-2-26

py -3.12 -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install -r requirements.txt
pip install pytest ruff
Copy-Item .env.example .env
```

Edit `.env` locally. Never commit it.

```powershell
$env:SECRET_KEY = "generate-a-unique-local-secret"
.\.venv\Scripts\python.exe app.py
```

The development server uses `http://127.0.0.1:5000`. Health check:

```powershell
Invoke-WebRequest http://127.0.0.1:5000/health
```

## Tests and lint

```powershell
.\.venv\Scripts\python.exe -m pytest -q
.\.venv\Scripts\ruff.exe check .
```

The smoke suite checks the health endpoint and anonymous home page.

## Docker and HTTPS on Ubuntu

Create `.env` from `.env.example`, then generate a VM-local certificate:

```bash
sudo apt-get update
sudo apt-get install -y openssl
chmod +x scripts/generate-self-signed-cert.sh
./scripts/generate-self-signed-cert.sh "$(hostname -I | awk '{print $1}')"
docker compose up --build -d
docker compose ps
curl -k https://localhost/health
```

The self-signed certificate is appropriate for a lab VM and will cause a
browser warning. For a real domain, use Certbot/Let's Encrypt and mount the
resulting `fullchain.pem` and `privkey.pem` as:

```text
nginx/certs/wynara.crt
nginx/certs/wynara.key
```

## Environment variables

Use [.env.example](./.env.example) as the placeholder-only template. Important
production variables include:

- `SECRET_KEY`
- `FLASK_ENV=production`
- `DATABASE_URL` when using PostgreSQL
- `GMAIL_USER` and `GMAIL_APP_PASSWORD`, or Resend variables
- `RAZORPAY_KEY_ID` and `RAZORPAY_KEY_SECRET`
- `APP_DOMAIN`
- `GRAFANA_ADMIN_PASSWORD` for the monitoring overlay

Secrets belong in GitHub Secrets, Ansible Vault, or a managed secret store.

## CI/CD

Pull requests and pushes to `main` run [.github/workflows/ci.yml](./.github/workflows/ci.yml):

1. Set up Python 3.12.
2. Run Ruff.
3. Run pytest.
4. Build the Docker image with Buildx.
5. Scan fixable HIGH and CRITICAL vulnerabilities with Trivy.
6. Push SHA and `latest` tags to GHCR on `main`.

After successful CI on `main`, [.github/workflows/deploy.yml](./.github/workflows/deploy.yml)
runs on the self-hosted Ubuntu runner. It pulls the exact commit-SHA image,
starts Compose without rebuilding, and checks `/health`.

Required repository secrets:

```text
GHCR_USERNAME
GHCR_TOKEN
```

`GHCR_TOKEN` needs read access to the package on the deployment VM. The VM
checkout must contain `.env` and the Nginx certificate files, but those files
must never be committed.

### Self-hosted runner setup

In GitHub, open **Settings -> Actions -> Runners -> New self-hosted runner**,
select **Linux x64**, and run the generated commands on the VM. Then install
the runner as a service:

```bash
sudo ./svc.sh install
sudo ./svc.sh start
```

The runner account needs permission to run Docker and access the deployment
checkout.

### Rollback

Set the repository variable `WYNARA_ROLLBACK_SHA` to a known-good image SHA and
rerun the deployment workflow. A manual rollback is:

```bash
export WYNARA_IMAGE=ghcr.io/dhannuchanda/wapl_dhannu_3-2-26
export WYNARA_TAG=<known-good-commit-sha>
docker compose pull web
docker compose up -d --no-build
curl --fail --silent --show-error --insecure https://127.0.0.1/health
```

## Infrastructure as Code

Ansible is the primary VM automation:

```bash
ansible-galaxy collection install -r ansible/requirements.yml
cp ansible/group_vars/all/vault.yml.example ansible/group_vars/all/vault.yml
ansible-vault encrypt ansible/group_vars/all/vault.yml
ansible-playbook -i ansible/inventory.ini ansible/site.yml \
  --ask-become-pass --ask-vault-pass
```

It installs Docker, creates the deploy user, configures UFW for ports 22, 80,
and 443, writes `.env` from Vault, and starts the stack.

Terraform under `terraform/` is an optional AWS EC2 example. It is not required
for the VirtualBox VM and never applies automatically:

```bash
cd terraform
terraform init
terraform fmt -check
terraform validate
terraform plan -out=tfplan
terraform apply tfplan
```

Use remote state and restrict `allowed_ssh_cidrs` before any real AWS use.

## Monitoring

Start the monitoring overlay after setting `GRAFANA_ADMIN_PASSWORD`:

```bash
docker compose \
  -f docker-compose.yml \
  -f docker-compose.monitoring.yml \
  up -d
```

The stack includes Prometheus, Grafana, node-exporter, and cAdvisor. Grafana
and Prometheus bind to localhost on the VM by default. The provisioned Grafana
dashboard shows:

- Request rate
- 5xx error rate
- p95 latency
- Container CPU and memory
- Host disk availability

Prometheus alerts include:

- `WynaraAppDown` after one minute
- `WynaraHigh5xxRate` above 5% for five minutes

## Design decisions

- **Multi-stage Docker build:** keeps the runtime image smaller and separates
  dependency construction from execution.
- **Non-root container user:** reduces the impact of a container compromise.
- **Nginx:** terminates TLS, applies security headers, limits upload size, and
  keeps Flask private to the Compose network.
- **Self-hosted runner:** a GitHub-hosted runner cannot reach a VM on the local
  VirtualBox network.
- **GHCR:** integrates image storage with GitHub and avoids an additional paid
  registry.
- **Trivy:** catches known image vulnerabilities before deployment.
- **Ansible:** provides repeatable, idempotent VM provisioning.
- **Prometheus/Grafana:** provides portable open-source metrics and dashboards.

## Problems I hit and how I solved them

Fill these in during the project presentation:

- Problem:
- Evidence:
- Root cause:
- Fix:
- Verification:
- Lesson learned:

## Screenshots

Add screenshots before presenting:

- [ ] Successful GitHub Actions CI run
- [ ] GHCR image and tags
- [ ] Ubuntu VM `docker compose ps`
- [ ] Running HTTPS application
- [ ] Grafana dashboard
- [ ] Prometheus alert rules

## Security and repository hygiene

Do not commit `.env`, private keys, databases, logs, uploads, Ansible Vault
files, Terraform state, or real Terraform variables. Rotate any credential
that has ever appeared in a committed file.

The repository previously contained generated upload files in Git tracking.
Remove them from the current index with:

```bash
git rm --cached -- \
  uploads/certificates/CERT20260122150836URDSPZ.pdf \
  uploads/certificates/certificate_wapl_id.jpg \
  uploads/qr_codes/CERT20260122150836URDSPZ_qr.png
git commit -m "chore: remove generated uploads from tracking"
```

Removing files from the index does not remove them from old commits. If
credentials or personal data were committed, rotate them and use a reviewed
history-rewrite process or a fresh repository before presenting the project.

## Related guides

- [DEPLOYMENT_GUIDE.md](./DEPLOYMENT_GUIDE.md)
- [ansible/README.md](./ansible/README.md)
- [terraform/README.md](./terraform/README.md)

## License

This project is licensed under the MIT License.
