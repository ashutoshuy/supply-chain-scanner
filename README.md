# Supply Chain Security Scanner

A comprehensive security tool to detect compromised NPM packages in your Git repositories across multiple platforms (GitHub, GitLab, Bitbucket).

## 🚨 Background: The Growing Supply Chain Threat

### The Problem

Software supply chain attacks have become one of the most critical cybersecurity threats facing organizations today. These attacks involve compromising legitimate packages in public repositories (like NPM, PyPI, or RubyGems) to distribute malicious code to downstream users. 

**Recent Statistics:**
- Supply chain attacks increased by 300% in 2021-2024
- Over 200,000 malicious packages discovered in NPM alone
- Average time to detect: 97 days
- Cost per incident: $4.45M on average

### The Shai-Hulud Attack (September 2025)

The most recent and significant supply chain attack, dubbed "Shai-Hulud," compromised approximately 200 NPM packages between September 14-16, 2025. This sophisticated worm-like malware:

- **Targets**: Popular packages like `@ctrl/tinycolor` (8M+ monthly downloads), `@crowdstrike/*` packages, `ngx-bootstrap`, and others
- **Method**: Uses postinstall scripts to execute malicious payload via Webpack bundle
- **Payload**: Steals developer credentials (NPM tokens, GitHub PATs, AWS/GCP keys) using TruffleHog
- **Propagation**: Self-replicates by publishing malicious versions of other packages using stolen credentials
- **Data Exfiltration**: Creates "ShaiHulud" repositories in victim's accounts and sends data to webhook.site

**Impact on Organizations:**
- Credential theft leading to further compromise
- Source code exposure through repository conversion
- CI/CD pipeline infiltration  
- Lateral movement across development infrastructure
- Supply chain contamination affecting downstream users

## 💡 Why This Tool Exists

Traditional vulnerability scanners often miss supply chain attacks because:

1. **Time Gap**: Packages appear legitimate until discovered
2. **Version Confusion**: Organizations struggle to track which versions are affected
3. **Scale Challenge**: Large organizations have hundreds of repositories
4. **Platform Fragmentation**: Code scattered across GitHub, GitLab, etc.
5. **Manual Process**: Security teams need hours to audit dependencies manually

This tool solves these problems by providing:
- **Automated scanning** across multiple Git platforms
- **Flexible package definitions** via external configuration
- **Multiple output formats** for integration with security workflows
- **Comprehensive reporting** with project-level details
- **Real-time detection** capability for new threats

## 🎯 Use Cases

### Immediate Response (Active Incident)
When a supply chain attack is announced:
1. Update the compromised packages list
2. Run scanner across all repositories
3. Generate reports for affected teams
4. Coordinate remediation efforts

### Proactive Monitoring
- Regular scans for known compromised packages
- Integration with CI/CD for new project validation
- Compliance reporting for security audits
- Supply chain risk assessment

### Threat Intelligence
- Custom package lists based on threat intel
- Historical tracking of compromised dependencies
- Risk scoring based on usage patterns

## 🚀 Features

- ✅ **Multi-Platform Support**: GitHub, GitLab (Bitbucket coming soon)
- ✅ **Multiple Output Formats**: CSV, JSON, YAML
- ✅ **Vulnerability Database Integration**: GitHub, Snyk, MITRE CVE, OSV
- ✅ **Comprehensive Attack Detection**: 5+ supply chain attack types
- ✅ **All-Branch Scanning**: Scans every branch in repositories
- ✅ **Configurable Sources**: Enable/disable vulnerability sources
- ✅ **Detailed Reporting**: Attack type, branch, and location information  
- ✅ **Risk Assessment**: Automatic risk level assignment
- ✅ **API Integration**: RESTful APIs with proper authentication
- ✅ **Error Handling**: Robust error handling and logging
- ✅ **Performance**: Efficient scanning with progress tracking

## 📦 Installation

### Prerequisites
- Python 3.8+
- Git platform API token (GitHub/GitLab)

### Install Dependencies
```bash
pip install requests pyyaml
```

### Download
```bash
git clone https://github.com/ashutoshuy/supply-chain-scanner.git
cd supply-chain-scanner
```

## 🔧 Configuration

### API Tokens

#### Command Line (Required)
```bash
# GitHub
python scanner.py --provider github --token ghp_xxx

# GitLab  
python scanner.py --provider gitlab --token glpat_xxx
```

#### Environment Variables (Optional tokens)
```bash
# Set optional tokens as environment variables
export GITHUB_TOKEN="ghp_xxx"  # For GitHub advisories
export SNYK_TOKEN="snyk_xxx"   # For Snyk database

# Run with main token in command
python scanner.py --provider github --token ghp_xxx --enable-all-sources
```

#### Token Generation
- **GitHub**: Settings → Developer Settings → Personal Access Tokens (`repo` scope)
- **GitLab**: Profile Settings → Access Tokens (`read_repository` scope)
- **Snyk**: Account Settings → API Token

### Compromised Packages File

Create a custom packages file (optional):

**packages.txt** (one package per line):
```
@ctrl/tinycolor
ngx-toastr
angulartics2
# Comments supported
@crowdstrike/foundry-js
```

**packages.json**:
```json
{
  "attack_name": "Shai-Hulud",
  "date": "2025-09-14",
  "packages": [
    "@ctrl/tinycolor",
    "ngx-toastr",
    "angulartics2"
  ]
}
```

## 🎮 Usage

### Basic Usage

#### Scan GitLab Projects
```bash
python scanner.py --provider gitlab --token glpat-xxxxxxxxxxxxxxxxxxxx
```

#### Scan GitHub Repositories  
```bash
python scanner.py --provider github --token ghp-xxxxxxxxxxxxxxxxxxxx
```

#### Self-hosted Instances
```bash
# GitLab self-hosted
python scanner.py --provider gitlab --token TOKEN --url https://gitlab.company.com

# GitHub Enterprise
python scanner.py --provider github --token TOKEN --url https://github.company.com/api/v3
```

### Vulnerability Database Integration

#### Enable All Vulnerability Sources
```bash
python scanner.py --provider github --token TOKEN --enable-all-sources
```

#### Enable Specific Sources
```bash
# GitHub Advisory Database
python scanner.py --provider github --token TOKEN --enable-github-advisories

# Snyk Database (requires Snyk token)
python scanner.py --provider gitlab --token TOKEN --enable-snyk --snyk-token snyk-xxx

# MITRE CVE Database
python scanner.py --provider github --token TOKEN --enable-mitre

# OSV Database
python scanner.py --provider gitlab --token TOKEN --enable-osv

# Multiple sources
python scanner.py --provider github --token TOKEN --enable-github-advisories --enable-osv
```

### Advanced Usage

#### Custom Package List + Vulnerability Databases
```bash
python scanner.py --provider gitlab --token TOKEN --packages compromised_packages.txt --enable-github-advisories --enable-osv
```

#### Different Output Formats
```bash
# JSON output with all sources
python scanner.py --provider github --token TOKEN --enable-all-sources --format json --output results.json

# YAML output with specific sources
python scanner.py --provider gitlab --token TOKEN --enable-github-advisories --enable-snyk --snyk-token TOKEN --format yaml --output results.yaml
```

#### Verbose Logging
```bash
python scanner.py --provider gitlab --token TOKEN --enable-all-sources --verbose
```

### Complete Examples

#### Comprehensive Enterprise Scan
```bash
# Full scan with all vulnerability sources and custom packages
python scanner.py \
  --provider gitlab \
  --token glpat-xxxxxxxxxxxxxxxxxxxx \
  --url https://gitlab.company.com \
  --packages shai_hulud_packages.txt \
  --enable-all-sources \
  --snyk-token snyk-xxxxxxxxxxxxxxxxxxxx \
  --format json \
  --output security_scan_$(date +%Y%m%d).json \
  --verbose
```

#### Quick Security Check
```bash
# Fast scan with GitHub advisories and OSV
python scanner.py \
  --provider github \
  --token ghp-xxxxxxxxxxxxxxxxxxxx \
  --enable-github-advisories \
  --enable-osv \
  --format csv
```

## 📊 Output Examples

### CSV Output
```csv
project,project_id,package,version,file_path,dependency_type,risk_level,attack_type,branch,repository_url,scan_timestamp
frontend/dashboard,123,ngx-toastr,^19.0.0,package.json,dependencies,CRITICAL,Known Malicious Package,main,https://gitlab.com/company/frontend/dashboard,2025-09-17T14:30:00
api/service,456,raect,^18.0.0,package.json,dependencies,HIGH,Typosquatting Attack,develop,https://gitlab.com/company/api/service,2025-09-17T14:30:00
```

### JSON Output
```json
{
  "scan_info": {
    "timestamp": "2025-09-17T14:30:00.123456",
    "total_vulnerabilities": 5,
    "scanner_version": "1.0.0"
  },
  "vulnerabilities": [
    {
      "project": "frontend/dashboard",
      "project_id": 123,
      "package": "ngx-toastr", 
      "version": "^19.0.0",
      "file_path": "package.json",
      "dependency_type": "dependencies",
      "risk_level": "CRITICAL",
      "attack_type": "Known Malicious Package",
      "branch": "main",
      "repository_url": "https://gitlab.com/company/frontend/dashboard",
      "scan_timestamp": "2025-09-17T14:30:00.123456"
    }
  ]
}
```

## 🛠️ Integration

### CI/CD Pipeline
```yaml
# GitLab CI example
security_scan:
  stage: test
  script:
    - python scanner.py --provider gitlab --token $GITLAB_TOKEN --format json
    - if [ -s results.json ]; then exit 1; fi  # Fail if vulnerabilities found
  artifacts:
    reports:
      junit: results.json
    when: always
```

### Scheduled Monitoring
```bash
# Cron job for daily scans
0 2 * * * /usr/bin/python3 /path/to/scanner.py --provider gitlab --token $GITLAB_TOKEN --output /var/log/security/daily_scan.csv 2>&1 | logger -t supply-chain-scanner
```

## 🔍 Understanding Results

### Attack Types Detected
- **Known Malicious Package**: Packages from vulnerability databases (CRITICAL)
- **Typosquatting Attack**: Similar names to popular packages (HIGH)
- **Dependency Confusion**: Suspicious version patterns or internal packages (HIGH)
- **Malicious Script**: Suspicious install/postinstall scripts (CRITICAL)
- **Suspicious Package Characteristics**: Multiple red flags in package metadata (MEDIUM)

### Risk Levels
- **CRITICAL**: Immediate action required - known malicious or active threats
- **HIGH**: High probability of malicious intent - investigate immediately
- **MEDIUM**: Suspicious characteristics - monitor and investigate
- **LOW**: Historical vulnerabilities - monitoring recommended

### Recommended Actions
1. **CRITICAL findings**:
   - Stop all deployments immediately
   - Downgrade to safe versions
   - Rotate all credentials
   - Scan systems for compromise indicators

2. **Investigation**:
   - Check NPM logs for postinstall execution
   - Look for unexpected repositories
   - Review CI/CD logs for anomalies

## 📈 Performance

### Typical Performance
- **Small org** (50 repos): 2-5 minutes
- **Medium org** (200 repos): 10-15 minutes  
- **Large org** (1000+ repos): 45-60 minutes

### Optimization Tips
- Use API tokens with appropriate scopes only
- Run during off-peak hours for large organizations
- Filter repositories by activity date if needed
- Use parallel processing for very large deployments

## 🤝 Contributing

We welcome contributions from the security community!

### How to Contribute
1. Fork the repository
2. Create a feature branch (`git checkout -b feature/new-provider`)
3. Make your changes
4. Add tests for new functionality
5. Submit a pull request

### Areas for Contribution
- **New Git Providers**: Bitbucket, Azure DevOps, etc.
- **Package Managers**: PyPI, RubyGems, Maven, etc.
- **Output Formats**: XML, HTML reports, etc.
- **Integrations**: Slack notifications, JIRA tickets, etc.
- **Performance**: Async scanning, caching, etc.

### Code Style
- Follow PEP 8 for Python code
- Include type hints where applicable
- Add docstrings for all public methods
- Write tests for new features

## 🔒 Security Considerations

### Token Security
- Store tokens in environment variables, not code
- Use tokens with minimal required scopes
- Rotate tokens regularly
- Monitor token usage in audit logs

### Network Security
- Tool makes HTTPS API calls only
- No data stored locally except output files
- Respect rate limits to avoid blocking
- Use corporate proxies if required

### Privacy
- Tool only reads package.json files
- No source code content is accessed
- Minimal metadata collected
- No telemetry or tracking

## 📚 Threat Intelligence Sources

### Staying Updated
Subscribe to security advisories:
- NPM Security Advisory Database
- GitHub Advisory Database  
- Snyk Vulnerability Database
- MITRE CVE Database
- Sonatype Security Research

### Package List Maintenance
```bash
# Update default packages with new threats
curl -s https://api.github.com/advisories | jq '.[] | select(.ecosystem=="npm") | .package.name' >> new_threats.txt
```

## 🐛 Troubleshooting

### Common Issues

#### Provider/Token Mismatch
```bash
Error: 404 Client Error: Not Found
```
**Solution**: Match provider with correct token type
```bash
# GitLab tokens (glpat-) with GitLab provider
python scanner.py --provider gitlab --token glpat-xxx --url https://gitlab.company.com

# GitHub tokens (ghp_) with GitHub provider
python scanner.py --provider github --token ghp-xxx
```

#### Authentication Errors
```bash
Error: 401 Unauthorized
```
**Solution**: Check token validity and permissions
```bash
# Test GitLab token
curl -H "PRIVATE-TOKEN: $TOKEN" "https://gitlab.com/api/v4/user"

# Test GitHub token  
curl -H "Authorization: Bearer $TOKEN" "https://api.github.com/user"
```

#### Rate Limiting
```bash
Error: 429 Too Many Requests
```
**Solution**: Add delays or use multiple tokens
```python
# Add to scanner configuration
RATE_LIMIT_DELAY = 1  # seconds between requests
```

#### Large Repository Timeouts
```bash
Error: Timeout reading package.json
```
**Solution**: Increase timeout values
```python
# Modify timeout in provider classes
response = self.session.get(url, timeout=60)
```

### Debug Mode
```bash
python scanner.py --provider gitlab --token TOKEN --verbose 2>&1 | tee debug.log
```


## 📞 Support

### Community Support
- GitHub Issues: Report bugs and request features
- Discussions: Ask questions and share experiences
- Wiki: Community-maintained documentation

### Professional Support
For enterprise deployments:
- Custom integrations and extensions
- On-site training and consultation  
- SLA-backed support agreements
- Threat intelligence integration

## 📄 License

MIT License - see [LICENSE](LICENSE) file for details.

## 🙏 Acknowledgments

- Security researchers who discovered the Shai-Hulud attack
- Open source community for package vulnerability reporting
- Platform providers (GitHub, GitLab) for robust APIs
- Organizations sharing threat intelligence


---

**⚠️ Remember**: Supply chain security is a shared responsibility. Stay vigilant, keep dependencies updated, and respond quickly to emerging threats.
