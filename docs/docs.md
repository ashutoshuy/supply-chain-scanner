---
layout: default
title: Documentation
---

# Complete Project Structure

Here's the complete directory structure for the open-source Supply Chain Security Scanner:

```
supply-chain-scanner/
├── scanner.py                     # Main scanner application
├── README.md                      # Comprehensive documentation
├── LICENSE                        # MIT license
├── setup.py                      # Package configuration
├── requirements.txt              # Runtime dependencies
├── requirements-dev.txt          # Development dependencies
├── Makefile                      # Build and development commands
├── Dockerfile                    # Container configuration
├── compromised_packages.txt      # Default package list
├── .github/
│   └── workflows/
│       └── ci.yml               # CI/CD pipeline
├── config/
│   └── packages.json            # Example JSON configuration
├── tests/
│   └── test_scanner.py          # Unit tests
├── examples/
│   ├── gitlab-ci.yml            # GitLab CI integration
│   ├── github-actions.yml       # GitHub Actions workflow
│   └── docker-compose.yml       # Docker deployment
├── docs/
│   ├── api.md                   # API documentation
│   ├── deployment.md            # Deployment guides
│   └── troubleshooting.md       # Common issues
└── CONTRIBUTING.md              # Contribution guidelines
```

## Quick Start Commands

### Installation
```bash
# Clone repository
git clone https://github.com/ashutoshuy/supply-chain-scanner.git
cd supply-chain-scanner

# Install dependencies
make install

# Or manual install
pip install -r requirements.txt
```

### Basic Usage
```bash
# Scan GitLab projects
python scanner.py --provider gitlab --token YOUR_TOKEN

# Scan GitHub repositories
python scanner.py --provider github --token YOUR_TOKEN

# Use custom package list
python scanner.py --provider gitlab --token TOKEN --packages compromised_packages.txt

# Output as JSON
python scanner.py --provider github --token TOKEN --format json --output results.json
```

### Development
```bash
# Run tests
make test

# Format code
make format

# Run linting
make lint

# Build package
make build

# Build Docker image
make docker
```

## Key Features Summary

### Multi-Platform Support
- **GitLab**: Self-hosted and GitLab.com
- **GitHub**: GitHub.com and Enterprise
- **Future**: Bitbucket, Azure DevOps

### Flexible Configuration  
- External package lists (TXT, JSON)
- Multiple output formats (CSV, JSON, YAML)
- Configurable scanning scope
- Custom risk levels

### Enterprise Ready
- Docker containerization
- CI/CD integration templates
- Comprehensive logging
- Error handling and recovery
- Rate limiting compliance

### Security Focused
- Token-based authentication
- Minimal data collection
- HTTPS-only communications
- No credential storage
- Audit trail support

## Integration Examples

### GitLab CI
```yaml
security_scan:
  stage: security
  image: securitycommunity/supply-chain-scanner:latest
  script:
    - python scanner.py --provider gitlab --token $GITLAB_TOKEN --format json
    - if [ -s results.json ]; then exit 1; fi
  artifacts:
    reports:
      junit: results.json
```

### GitHub Actions
```yaml
- name: Supply Chain Scan
  run: |
    python scanner.py --provider github --token ${{ secrets.GITHUB_TOKEN }} --format json
    if [ -s results.json ]; then exit 1; fi
```

### Docker Deployment
```bash
# Run with environment variables
docker run -e GITLAB_TOKEN=$TOKEN securitycommunity/supply-chain-scanner:latest \
  --provider gitlab --format json --output /app/results.json

# Mount volume for results
docker run -v $(pwd):/output securitycommunity/supply-chain-scanner:latest \
  --provider github --token $GITHUB_TOKEN --output /output/scan.csv
```

## Customization

### Custom Package Lists
Create your own package definitions:

**simple.txt**:
```
@ctrl/tinycolor
ngx-toastr  
lodash
```

**detailed.json**:
```json
{
  "threat_name": "Custom Threat",
  "packages": ["package1", "package2"],
  "metadata": {
    "severity": "HIGH",
    "discovery_date": "2025-09-17"
  }
}
```

### Environment Configuration
```bash
# Set tokens via environment
export GITLAB_TOKEN="glpat-xxxxxxxxxxxxxxxxxxxx"
export GITHUB_TOKEN="ghp-xxxxxxxxxxxxxxxxxxxx"

# Run without specifying token
python scanner.py --provider gitlab --format json
```

## Deployment Scenarios

### Incident Response
```bash
# Emergency scan across all platforms
./emergency-scan.sh

# Content of emergency-scan.sh:
#!/bin/bash
python scanner.py --provider gitlab --token $GITLAB_TOKEN --format json --output gitlab-$(date +%Y%m%d).json &
python scanner.py --provider github --token $GITHUB_TOKEN --format json --output github-$(date +%Y%m%d).json &
wait
echo "Emergency scan completed"
```

### Scheduled Monitoring
```bash
# Cron job for daily scans
0 2 * * * cd /opt/scanner && python scanner.py --provider gitlab --token $GITLAB_TOKEN --output /var/log/daily-scan.csv
```

### CI/CD Pipeline Integration
The scanner can be integrated into various CI/CD platforms to automatically check for vulnerabilities in new code or deployments.

This complete package provides everything needed for a professional open-source security tool that addresses the critical supply chain vulnerability problem affecting modern software development.