# SecureVault - Secure Credential Management System

A secure credential storage system built with Flask and PostgreSQL, featuring role-based access control (RBAC) and Azure integration.

## Features

- Secure credential storage with encryption
- Role-based access control (RBAC)
- Azure AD OAuth authentication
- Azure Key Vault integration for secure key management
- Credential sharing capabilities
- User and role management
- Docker and Kubernetes deployment support

## Prerequisites

- Python 3.11+
- PostgreSQL
- Docker and Docker Compose
- Azure subscription with:
  - Azure AD application registration
  - Azure Key Vault
  - Azure Container Registry (for deployment)

## Local Development Setup

1. Clone the repository:
```bash
git clone https://github.com/yourusername/securevault.git
cd securevault
```

2. Create and activate a virtual environment:
```bash
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate
```

3. Install dependencies:
```bash
pip install -r requirements.txt
```

4. Set up environment variables:
Create a `.env` file with the following variables:
```
DATABASE_URL=postgresql://postgres:postgres@localhost:5432/securevault
SECRET_KEY=your-secret-key
AZURE_KEY_VAULT_URL=https://your-keyvault.vault.azure.net/
AZURE_TENANT_ID=your-tenant-id
AZURE_CLIENT_ID=your-client-id
AZURE_CLIENT_SECRET=your-client-secret
```

5. Initialize the database:
```bash
flask db init
flask db migrate
flask db upgrade
```

6. Run the development server:
```bash
flask run
```

## Docker Development Setup

1. Build and start the containers:
```bash
docker-compose up --build
```

2. Initialize the database:
```bash
docker-compose exec web flask db init
docker-compose exec web flask db migrate
docker-compose exec web flask db upgrade
```

## Azure Deployment

1. Build and push the Docker image:
```bash
docker build -t yourregistry.azurecr.io/securevault:latest .
docker push yourregistry.azurecr.io/securevault:latest
```

2. Deploy to Azure Kubernetes Service (AKS):
```bash
kubectl apply -f k8s/
```

## Security Features

- All credentials are encrypted using Fernet symmetric encryption
- Encryption keys are stored in Azure Key Vault
- Role-based access control for user management
- Azure AD OAuth authentication
- Secure credential sharing with access control
- Password hashing using Werkzeug's security functions

## Contributing

1. Fork the repository
2. Create a feature branch
3. Commit your changes
4. Push to the branch
5. Create a Pull Request

## License

This project is licensed under the MIT License - see the LICENSE file for details.

## Secrets Management

### Local Development
1. Copy `k8s/secrets.yaml.example` to `k8s/secrets.yaml`
2. Generate base64 encoded values for your secrets:
```bash
# Example for database URL
echo -n "postgresql://user:password@localhost:5432/securevault" | base64

# Example for secret key
echo -n "your-secret-key" | base64
```
3. Replace the placeholder values in `k8s/secrets.yaml` with your encoded secrets

### Production Deployment
1. Create a Kubernetes secret in your cluster:
```bash
kubectl create secret generic securevault-secrets \
  --from-literal=database-url='your-database-url' \
  --from-literal=secret-key='your-secret-key' \
  --from-literal=azure-keyvault-url='your-keyvault-url' \
  --from-literal=azure-tenant-id='your-tenant-id' \
  --from-literal=azure-client-id='your-client-id' \
  --from-literal=azure-client-secret='your-client-secret'
```

2. Verify the secret was created:
```bash
kubectl get secret securevault-secrets -o yaml
```

### Security Notes
- Never commit `k8s/secrets.yaml` to version control
- Use different secrets for development and production
- Rotate secrets regularly
- Use Azure Key Vault for production secrets management
- Consider using a secrets management solution like HashiCorp Vault or Azure Key Vault 