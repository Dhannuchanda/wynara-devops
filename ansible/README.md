# Ansible deployment

This playbook provisions a blank Ubuntu VM and deploys the Compose stack. It
does not run automatically from Terraform or GitHub Actions.

## One-time setup

1. Copy `inventory.ini` to a private location and replace `ansible_host`.
2. Install the required Ansible collection:

```bash
ansible-galaxy collection install -r ansible/requirements.yml
```

3. Create the encrypted variables file:

```bash
cp ansible/group_vars/all/vault.yml.example ansible/group_vars/all/vault.yml
$EDITOR ansible/group_vars/all/vault.yml
ansible-vault encrypt ansible/group_vars/all/vault.yml
```

4. Create the self-signed certificate on the VM after the repository is cloned:

```bash
cd /opt/wynara
chmod +x scripts/generate-self-signed-cert.sh
./scripts/generate-self-signed-cert.sh "$(hostname -I | awk '{print $1}')"
```

## Run

```bash
ansible-playbook -i ansible/inventory.ini ansible/site.yml \
  --ask-become-pass --ask-vault-pass
```

The playbook creates the `wynara` deploy user, installs Docker and Compose,
configures UFW for SSH/HTTP/HTTPS, checks out the configured repository, writes
`.env` from the vault, and starts the stack idempotently.
