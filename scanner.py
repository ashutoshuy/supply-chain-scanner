#!/usr/bin/env python3
"""
Supply Chain Security Scanner
A tool to detect compromised NPM packages in Git repositories

Supports: GitHub, GitLab, Bitbucket
Output formats: JSON, CSV, YAML
"""

import requests
import json
import csv
import yaml
import argparse
import sys
import os
from datetime import datetime, timedelta
from typing import List, Dict, Optional, Union, Any, Set
from pathlib import Path
import urllib.parse
import logging
from dataclasses import dataclass, asdict
import time

__version__ = "1.0.0"
__author__ = "Security Community"
__license__ = "MIT"

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

class VulnerabilityDatabase:
    """Vulnerability database integration with multiple sources"""
    
    def __init__(self, github_token: Optional[str] = None, snyk_token: Optional[str] = None):
        self.github_token = github_token
        self.snyk_token = snyk_token
        self.session = requests.Session()
        self.session.headers.update({'User-Agent': 'supply-chain-scanner/1.0.0'})
    
    def get_npm_advisories(self) -> Set[str]:
        """Get vulnerable packages from NPM Security Advisory Database"""
        logger.warning("NPM Advisory API is not publicly available, skipping NPM advisories")
        return set()
    
    def get_github_advisories(self) -> Set[str]:
        """Get vulnerable packages from GitHub Advisory Database"""
        if not self.github_token:
            logger.warning("GitHub token not provided, skipping GitHub advisories")
            return set()
        
        try:
            headers = {
                'Authorization': f'Bearer {self.github_token}',
                'Accept': 'application/vnd.github+json',
                'X-GitHub-Api-Version': '2022-11-28'
            }
            url = "https://api.github.com/advisories"
            params = {'ecosystem': 'npm', 'per_page': 100}
            
            packages = set()
            page = 1
            
            while page <= 3:  # Limit to 3 pages
                params['page'] = page
                response = self.session.get(url, headers=headers, params=params, timeout=30)
                response.raise_for_status()
                
                advisories = response.json()
                if not advisories:
                    break
                
                for advisory in advisories:
                    for vuln in advisory.get('vulnerabilities', []):
                        if vuln.get('package', {}).get('ecosystem') == 'npm':
                            packages.add(vuln['package']['name'])
                
                page += 1
                time.sleep(1)  # Rate limiting
            
            logger.info(f"Loaded {len(packages)} packages from GitHub Advisory Database")
            return packages
        except Exception as e:
            logger.error(f"Failed to fetch GitHub advisories: {e}")
            return set()
    
    def get_snyk_advisories(self) -> Set[str]:
        """Get vulnerable packages from Snyk Database"""
        if not self.snyk_token:
            logger.warning("Snyk token not provided, skipping Snyk advisories")
            return set()
        
        try:
            headers = {'Authorization': f'token {self.snyk_token}'}
            url = "https://api.snyk.io/v1/vuln/npm"
            
            response = self.session.get(url, headers=headers, timeout=30)
            response.raise_for_status()
            
            data = response.json()
            packages = set()
            
            for vuln in data.get('vulnerabilities', []):
                if 'package' in vuln:
                    packages.add(vuln['package'])
            
            logger.info(f"Loaded {len(packages)} packages from Snyk Database")
            return packages
        except Exception as e:
            logger.error(f"Failed to fetch Snyk advisories: {e}")
            return set()
    
    def get_mitre_cve_packages(self) -> Set[str]:
        """Get NPM packages from MITRE CVE Database"""
        try:
            # Using NVD API for CVE data
            url = "https://services.nvd.nist.gov/rest/json/cves/2.0"
            params = {'keywordSearch': 'npm package', 'resultsPerPage': 100}
            
            response = self.session.get(url, params=params, timeout=30)
            response.raise_for_status()
            
            data = response.json()
            packages = set()
            
            for cve in data.get('vulnerabilities', []):
                description = cve.get('cve', {}).get('description', {}).get('description_data', [{}])[0].get('value', '')
                # Simple pattern matching for NPM package names
                import re
                npm_packages = re.findall(r'npm\s+package\s+([\w@/-]+)', description, re.IGNORECASE)
                packages.update(npm_packages)
            
            logger.info(f"Loaded {len(packages)} packages from MITRE CVE Database")
            return packages
        except Exception as e:
            logger.error(f"Failed to fetch MITRE CVE data: {e}")
            return set()
    
    def get_osv_advisories(self) -> Set[str]:
        """Get vulnerable packages from OSV (Open Source Vulnerabilities) Database"""
        try:
            # Query for popular npm packages to get vulnerabilities
            popular_packages = ['lodash', 'express', 'react', 'axios', 'moment']
            packages = set()
            
            for pkg in popular_packages:
                url = "https://api.osv.dev/v1/query"
                payload = {
                    "package": {
                        "ecosystem": "npm",
                        "name": pkg
                    }
                }
                
                response = self.session.post(url, json=payload, timeout=30)
                if response.status_code == 200:
                    data = response.json()
                    for vuln in data.get('vulns', []):
                        for affected in vuln.get('affected', []):
                            if affected.get('package', {}).get('ecosystem') == 'npm':
                                packages.add(affected['package']['name'])
                
                time.sleep(0.1)  # Rate limiting
            
            logger.info(f"Loaded {len(packages)} packages from OSV Database")
            return packages
        except Exception as e:
            logger.error(f"Failed to fetch OSV advisories: {e}")
            return set()
    
    def get_all_vulnerable_packages(self, sources: Dict[str, bool]) -> Set[str]:
        """Get vulnerable packages from enabled sources"""
        all_packages = set()
        

        
        if sources.get('github', False):
            all_packages.update(self.get_github_advisories())
        
        if sources.get('snyk', False):
            all_packages.update(self.get_snyk_advisories())
        
        if sources.get('mitre', False):
            all_packages.update(self.get_mitre_cve_packages())
        
        if sources.get('osv', False):
            all_packages.update(self.get_osv_advisories())
        
        logger.info(f"Total unique vulnerable packages: {len(all_packages)}")
        return all_packages

@dataclass
class Vulnerability:
    """Data class for vulnerability information"""
    project: str
    project_id: Union[str, int]
    package: str
    version: str
    file_path: str
    dependency_type: str
    risk_level: str
    attack_type: str = ""
    branch: str = ""
    repository_url: str = ""
    scan_timestamp: str = ""
    
    def __post_init__(self):
        if not self.scan_timestamp:
            self.scan_timestamp = datetime.now().isoformat()

class SupplyChainAttackDetector:
    """Detect various types of supply chain attacks"""
    
    def __init__(self, compromised_packages: Set[str]):
        self.compromised_packages = compromised_packages
        self.popular_packages = {
            'react', 'lodash', 'express', 'axios', 'moment', 'webpack', 'babel',
            'eslint', 'typescript', 'jquery', 'bootstrap', 'angular', 'vue'
        }
    
    def detect_typosquatting(self, package_name: str) -> bool:
        """Detect potential typosquatting attacks"""
        import difflib
        for popular in self.popular_packages:
            if package_name != popular:
                similarity = difflib.SequenceMatcher(None, package_name.lower(), popular.lower()).ratio()
                if 0.7 <= similarity < 1.0:
                    return True
        return False
    
    def detect_dependency_confusion(self, package_name: str, version: str) -> bool:
        """Detect dependency confusion attacks"""
        import re
        suspicious_versions = [r'^999\.', r'^\d{10,}', r'\.(999|9999)\.']        
        for pattern in suspicious_versions:
            if re.match(pattern, version.strip('^~>=<')):
                return True        
        internal_patterns = ['@company/', '@internal/', '@private/']
        return any(package_name.startswith(pattern) for pattern in internal_patterns)
    
    def detect_malicious_scripts(self, package_json: Dict) -> List[str]:
        """Detect malicious install scripts"""
        malicious_scripts = []
        scripts = package_json.get('scripts', {})
        suspicious_domains = ['webhook.site', 'requestbin.com', 'ngrok.io']
        crypto_miners = ['cryptonight', 'monero', 'bitcoin', 'mining']
        
        for script_type in ['postinstall', 'preinstall', 'install']:
            if script_type in scripts:
                script_content = scripts[script_type].lower()
                if any(domain in script_content for domain in suspicious_domains):
                    malicious_scripts.append(f"{script_type}: external data exfiltration")
                elif any(crypto in script_content for crypto in crypto_miners):
                    malicious_scripts.append(f"{script_type}: cryptocurrency mining")
                elif 'curl' in script_content or 'wget' in script_content:
                    malicious_scripts.append(f"{script_type}: suspicious network activity")
                elif 'rm -rf' in script_content or 'del /f' in script_content:
                    malicious_scripts.append(f"{script_type}: destructive commands")
        
        return malicious_scripts
    
    def detect_backdoor_packages(self, package_name: str, package_json: Dict) -> bool:
        """Detect potential backdoor packages"""
        suspicious_indicators = [
            len(package_json.get('description', '')) < 10,
            not package_json.get('repository'),
            not package_json.get('homepage'),
            package_json.get('version', '').startswith('0.0.'),
        ]
        return sum(suspicious_indicators) >= 3
    
    def detect_supply_chain_attacks(self, package_name: str, version: str, package_json: Dict) -> List[Dict[str, str]]:
        """Detect all types of supply chain attacks"""
        attacks = []
        
        if package_name in self.compromised_packages:
            attacks.append({'type': 'Known Malicious Package', 'severity': 'CRITICAL'})
        
        if self.detect_typosquatting(package_name):
            attacks.append({'type': 'Typosquatting Attack', 'severity': 'HIGH'})
        
        if self.detect_dependency_confusion(package_name, version):
            attacks.append({'type': 'Dependency Confusion', 'severity': 'HIGH'})
        
        malicious_scripts = self.detect_malicious_scripts(package_json)
        for script in malicious_scripts:
            attacks.append({'type': f'Malicious Script: {script}', 'severity': 'CRITICAL'})
        
        if self.detect_backdoor_packages(package_name, package_json):
            attacks.append({'type': 'Suspicious Package Characteristics', 'severity': 'MEDIUM'})
        
        return attacks

class GitProvider:
    """Base class for Git providers"""
    
    def __init__(self, base_url: str, token: str):
        self.base_url = base_url.rstrip('/')
        self.token = token
        self.session = requests.Session()
        self._setup_auth()
    
    def _setup_auth(self) -> None:
        """Setup authentication headers"""
        raise NotImplementedError
    
    def get_projects(self) -> List[Dict]:
        """Get all accessible projects"""
        raise NotImplementedError
    
    def get_branches(self, project_id: Union[str, int]) -> List[str]:
        """Get all branches for a project"""
        raise NotImplementedError
    
    def get_package_files(self, project_id: Union[str, int], branch: str) -> List[str]:
        """Get package.json files in project branch"""
        raise NotImplementedError
    
    def get_file_content(self, project_id: Union[str, int], file_path: str, branch: str) -> Optional[Dict]:
        """Get content of package.json file from specific branch"""
        raise NotImplementedError

class GitLabProvider(GitProvider):
    """GitLab API provider"""
    
    def _setup_auth(self) -> None:
        self.session.headers.update({'PRIVATE-TOKEN': self.token})
    
    def get_projects(self) -> List[Dict]:
        projects = []
        page = 1
        per_page = 100
        
        logger.info("Fetching GitLab projects...")
        while True:
            url = f"{self.base_url}/api/v4/projects"
            params: Dict[str, Union[str, int]] = {
                'membership': 'true',
                'per_page': per_page,
                'page': page,
                'simple': 'true'
            }
            
            try:
                response = self.session.get(url, params=params, timeout=30)
                response.raise_for_status()
                batch = response.json()
                
                if not batch:
                    break
                
                projects.extend(batch)
                logger.info(f"Fetched {len(projects)} projects so far...")
                page += 1
                
            except requests.RequestException as e:
                logger.error(f"Error fetching projects: {e}")
                raise
        
        logger.info(f"Total projects found: {len(projects)}")
        return projects
    
    def get_branches(self, project_id: Union[str, int]) -> List[str]:
        try:
            url = f"{self.base_url}/api/v4/projects/{project_id}/repository/branches"
            response = self.session.get(url, timeout=30)
            if response.status_code == 404:
                return []
            response.raise_for_status()
            branches = response.json()
            return [branch['name'] for branch in branches]
        except requests.RequestException:
            return []
    
    def get_package_files(self, project_id: Union[str, int], branch: str) -> List[str]:
        try:
            url = f"{self.base_url}/api/v4/projects/{project_id}/repository/tree"
            params: Dict[str, Union[str, int]] = {'recursive': 'true', 'per_page': 100, 'ref': branch}
            
            response = self.session.get(url, params=params, timeout=30)
            if response.status_code == 404:
                return []
            
            response.raise_for_status()
            tree = response.json()
            
            return [item['path'] for item in tree 
                   if item['name'] == 'package.json' and item['type'] == 'blob']
                   
        except requests.RequestException:
            return []
    
    def get_file_content(self, project_id: Union[str, int], file_path: str, branch: str) -> Optional[Dict]:
        encoded_path = urllib.parse.quote(file_path, safe='')
        
        try:
            url = f"{self.base_url}/api/v4/projects/{project_id}/repository/files/{encoded_path}/raw"
            params: Dict[str, str] = {'ref': branch}
            
            response = self.session.get(url, params=params, timeout=30)
            if response.status_code == 200:
                return json.loads(response.text)
        except (requests.RequestException, json.JSONDecodeError):
            pass
        
        return None

class GitHubProvider(GitProvider):
    """GitHub API provider"""
    
    def _setup_auth(self) -> None:
        self.session.headers.update({
            'Authorization': f'Bearer {self.token}',
            'Accept': 'application/vnd.github+json',
            'X-GitHub-Api-Version': '2022-11-28'
        })
    
    def get_projects(self) -> List[Dict]:
        projects = []
        page = 1
        per_page = 100
        
        logger.info("Fetching GitHub repositories...")
        while True:
            url = f"{self.base_url}/user/repos"
            params: Dict[str, Union[str, int]] = {
                'per_page': per_page,
                'page': page,
                'type': 'all',
                'sort': 'updated'
            }
            
            try:
                response = self.session.get(url, params=params, timeout=30)
                response.raise_for_status()
                batch = response.json()
                
                if not batch:
                    break
                
                # Transform GitHub format to match GitLab structure
                for repo in batch:
                    projects.append({
                        'id': repo['id'],
                        'name': repo['name'],
                        'path_with_namespace': repo['full_name'],
                        'web_url': repo['html_url']
                    })
                
                logger.info(f"Fetched {len(projects)} repositories so far...")
                page += 1
                
            except requests.RequestException as e:
                logger.error(f"Error fetching repositories: {e}")
                raise
        
        logger.info(f"Total repositories found: {len(projects)}")
        return projects
    
    def get_branches(self, project_id: Union[str, int]) -> List[str]:
        try:
            repo_response = self.session.get(f"{self.base_url}/repositories/{project_id}")
            repo_response.raise_for_status()
            repo_info = repo_response.json()
            
            url = f"{self.base_url}/repos/{repo_info['full_name']}/branches"
            response = self.session.get(url, timeout=30)
            if response.status_code == 404:
                return []
            response.raise_for_status()
            branches = response.json()
            return [branch['name'] for branch in branches]
        except requests.RequestException:
            return []
    
    def get_package_files(self, project_id: Union[str, int], branch: str) -> List[str]:
        try:
            repo_response = self.session.get(f"{self.base_url}/repositories/{project_id}")
            repo_response.raise_for_status()
            repo_info = repo_response.json()
            
            url = f"{self.base_url}/repos/{repo_info['full_name']}/git/trees/{branch}"
            params: Dict[str, str] = {'recursive': '1'}
            
            response = self.session.get(url, params=params, timeout=30)
            if response.status_code == 404:
                return []
            
            response.raise_for_status()
            tree = response.json()
            
            return [item['path'] for item in tree.get('tree', [])
                   if item['path'].endswith('package.json') and item['type'] == 'blob']
                   
        except requests.RequestException:
            return []
    
    def get_file_content(self, project_id: Union[str, int], file_path: str, branch: str) -> Optional[Dict]:
        try:
            repo_response = self.session.get(f"{self.base_url}/repositories/{project_id}")
            repo_response.raise_for_status()
            repo_info = repo_response.json()
            
            url = f"{self.base_url}/repos/{repo_info['full_name']}/contents/{file_path}"
            params = {'ref': branch}
            
            response = self.session.get(url, params=params, timeout=30)
            if response.status_code == 200:
                content_info = response.json()
                if content_info['encoding'] == 'base64':
                    import base64
                    content = base64.b64decode(content_info['content']).decode('utf-8')
                    return json.loads(content)
            
        except (requests.RequestException, json.JSONDecodeError, KeyError):
            pass
        
        return None

class SupplyChainScanner:
    """Main scanner class"""
    
    def __init__(self, provider: GitProvider, compromised_packages: List[str]):
        self.provider = provider
        self.compromised_packages = set(compromised_packages)
        self.attack_detector = SupplyChainAttackDetector(self.compromised_packages)
        
    @classmethod
    def create_provider(cls, provider_type: str, base_url: str, token: str) -> GitProvider:
        """Factory method for creating providers"""
        providers = {
            'gitlab': GitLabProvider,
            'github': GitHubProvider,
        }
        
        if provider_type.lower() not in providers:
            raise ValueError(f"Unsupported provider: {provider_type}")
        
        return providers[provider_type.lower()](base_url, token)
    
    @classmethod
    def load_compromised_packages(cls, package_file: Optional[str] = None, 
                                vuln_sources: Optional[Dict[str, bool]] = None,
                                github_token: Optional[str] = None,
                                snyk_token: Optional[str] = None) -> List[str]:
        """Load compromised packages from file, vulnerability databases, or use defaults"""
        packages = set()
        
        # Load from file if provided
        if package_file and Path(package_file).exists():
            logger.info(f"Loading compromised packages from {package_file}")
            with open(package_file, 'r') as f:
                if package_file.endswith('.json'):
                    data = json.load(f)
                    file_packages = data.get('packages', data) if isinstance(data, dict) else data
                    packages.update(file_packages or [])
                else:
                    packages.update([line.strip() for line in f if line.strip() and not line.startswith('#')])
        
        # Load from vulnerability databases if enabled
        if vuln_sources and any(vuln_sources.values()):
            logger.info("Loading packages from vulnerability databases...")
            vuln_db = VulnerabilityDatabase(github_token, snyk_token)
            db_packages = vuln_db.get_all_vulnerable_packages(vuln_sources)
            packages.update(db_packages)
        
        # Use defaults if no other sources
        if not packages:
            logger.info("Using default Shai-Hulud compromised packages list")
            packages.update(cls._get_default_packages())
        
        return list(packages)
    
    @staticmethod
    def _get_default_packages() -> List[str]:
        """Default list of compromised packages from Shai-Hulud attack"""
        return [
            "@ahmedhfarag/ngx-perfect-scrollbar", "@ahmedhfarag/ngx-virtual-scroller",
            "@art-ws/common", "@art-ws/config-eslint", "@art-ws/config-ts", "@art-ws/db-context",
            "@art-ws/di", "@art-ws/di-node", "@art-ws/eslint", "@art-ws/fastify-http-server",
            "@art-ws/http-server", "@art-ws/openapi", "@art-ws/package-base", "@art-ws/prettier",
            "@art-ws/slf", "@art-ws/ssl-info", "@art-ws/web-app", "@crowdstrike/commitlint",
            "@crowdstrike/falcon-shoelace", "@crowdstrike/foundry-js", "@crowdstrike/glide-core",
            "@crowdstrike/logscale-dashboard", "@crowdstrike/logscale-file-editor",
            "@crowdstrike/logscale-parser-edit", "@crowdstrike/logscale-search",
            "@crowdstrike/tailwind-toucan-base", "@ctrl/deluge", "@ctrl/golang-template",
            "@ctrl/magnet-link", "@ctrl/ngx-codemirror", "@ctrl/ngx-csv", "@ctrl/ngx-emoji-mart",
            "@ctrl/ngx-rightclick", "@ctrl/qbittorrent", "@ctrl/react-adsense", "@ctrl/shared-torrent",
            "@ctrl/tinycolor", "@ctrl/torrent-file", "@ctrl/transmission", "@ctrl/ts-base32",
            "angulartics2", "browser-webdriver-downloader", "capacitor-notificationhandler",
            "capacitor-plugin-healthapp", "capacitor-plugin-ihealth", "capacitor-plugin-vonage",
            "capacitorandroidpermissions", "config-cordova", "cordova-plugin-voxeet2",
            "cordova-voxeet", "create-hest-app", "db-evo", "devextreme-angular-rpk",
            "ember-browser-services", "ember-headless-form", "ember-headless-form-yup",
            "ember-headless-table", "ember-url-hash-polyfill", "ember-velcro",
            "encounter-playground", "eslint-config-crowdstrike", "eslint-config-crowdstrike-node",
            "eslint-config-teselagen", "globalize-rpk", "graphql-sequelize-teselagen",
            "html-to-base64-image", "json-rules-engine-simplified", "jumpgate", "koa2-swagger-ui",
            "mcfly-semantic-release", "mcp-knowledge-base", "mcp-knowledge-graph",
            "mobioffice-cli", "monorepo-next", "ng2-file-upload", "ngx-bootstrap", "ngx-color",
            "ngx-toastr", "ngx-trend", "ngx-ws", "pm2-gelf-json", "printjs-rpk",
            "react-complaint-image", "react-jsonschema-form-conditionals",
            "remark-preset-lint-crowdstrike", "rxnt-authentication", "rxnt-healthchecks-nestjs",
            "rxnt-kue", "swc-plugin-component-annotate", "tbssnch", "teselagen-interval-tree",
            "tg-client-query-builder", "tg-redbird", "tg-seq-gen", "thangved-react-grid",
            "ts-gaussian", "ts-imports", "tvi-cli", "ve-bamreader", "ve-editor", "verror-extra",
            "voip-callkit", "wdio-web-reporter", "yargs-help-output", "yoo-styles"
        ]
    
    def scan_project(self, project: Dict) -> List[Vulnerability]:
        """Scan a single project for compromised packages across all branches"""
        vulnerabilities = []
        project_name = project['path_with_namespace']
        project_id = project['id']
        
        logger.info(f"Scanning: {project_name}")
        
        branches = self.provider.get_branches(project_id)
        if not branches:
            return vulnerabilities
        
        for branch in branches:
            package_files = self.provider.get_package_files(project_id, branch)
            
            for file_path in package_files:
                package_json = self.provider.get_file_content(project_id, file_path, branch)
                if not package_json:
                    continue
                
                # Check dependencies and devDependencies
                for dep_type in ['dependencies', 'devDependencies']:
                    deps = package_json.get(dep_type, {})
                    
                    for package_name, version in deps.items():
                        attacks = self.attack_detector.detect_supply_chain_attacks(package_name, version, package_json)
                        
                        for attack in attacks:
                            vuln = Vulnerability(
                                project=project_name,
                                project_id=project_id,
                                package=package_name,
                                version=version,
                                file_path=file_path,
                                dependency_type=dep_type,
                                risk_level=attack['severity'],
                                attack_type=attack['type'],
                                branch=branch,
                                repository_url=project.get('web_url', '')
                            )
                            vulnerabilities.append(vuln)
                            logger.warning(f"Found {attack['type']}: {package_name}@{version} in {file_path} (branch: {branch})")
        
        return vulnerabilities
    
    def scan_all_projects(self) -> List[Vulnerability]:
        """Scan all projects and return vulnerabilities"""
        projects = self.provider.get_projects()
        all_vulnerabilities = []
        
        logger.info(f"Scanning {len(projects)} projects for vulnerabilities...")
        
        for i, project in enumerate(projects, 1):
            logger.info(f"Progress: {i}/{len(projects)}")
            try:
                vulnerabilities = self.scan_project(project)
                all_vulnerabilities.extend(vulnerabilities)
            except Exception as e:
                logger.error(f"Error scanning {project['path_with_namespace']}: {e}")
        
        return all_vulnerabilities
    
    def export_results(self, vulnerabilities: List[Vulnerability], 
                      output_file: str, format_type: str = 'csv') -> None:
        """Export results in specified format"""
        if not vulnerabilities:
            logger.info("No vulnerabilities found to export")
            return
        
        data = [asdict(vuln) for vuln in vulnerabilities]
        
        if format_type.lower() == 'json':
            with open(output_file, 'w', encoding='utf-8') as f:
                json.dump({
                    'scan_info': {
                        'timestamp': datetime.now().isoformat(),
                        'total_vulnerabilities': len(vulnerabilities),
                        'scanner_version': __version__
                    },
                    'vulnerabilities': data
                }, f, indent=2, ensure_ascii=False)
        
        elif format_type.lower() == 'yaml':
            with open(output_file, 'w', encoding='utf-8') as f:
                yaml.dump({
                    'scan_info': {
                        'timestamp': datetime.now().isoformat(),
                        'total_vulnerabilities': len(vulnerabilities),
                        'scanner_version': __version__
                    },
                    'vulnerabilities': data
                }, f, default_flow_style=False)
        
        else:  # CSV
            with open(output_file, 'w', newline='', encoding='utf-8') as f:
                if data:
                    fieldnames = list(data[0].keys())
                    writer = csv.DictWriter(f, fieldnames=fieldnames)
                    writer.writeheader()
                    writer.writerows(data)
        
        logger.info(f"Results exported to {output_file}")

def main() -> None:
    parser = argparse.ArgumentParser(
        description='Supply Chain Security Scanner - Detect compromised NPM packages',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Scan GitLab projects
  python scanner.py --provider gitlab --token glpat-xxx --url https://gitlab.company.com
  
  # Scan GitHub repositories with GitHub advisories
  python scanner.py --provider github --token ghp-xxx --enable-github-advisories
  
  # Use specific vulnerability sources
  python scanner.py --provider gitlab --token xxx --enable-github-advisories --enable-osv
  
  # Use custom package list and Snyk database
  python scanner.py --provider gitlab --token xxx --packages packages.txt --enable-snyk --snyk-token snyk-xxx
        """
    )
    
    parser.add_argument('--provider', required=True, choices=['gitlab', 'github'], 
                       help='Git provider (gitlab or github)')
    parser.add_argument('--token', required=True, help='API token for authentication')
    parser.add_argument('--url', help='Provider URL (default: https://gitlab.com or https://api.github.com)')
    parser.add_argument('--packages', help='File containing compromised packages list')
    parser.add_argument('--output', help='Output file name')
    parser.add_argument('--format', choices=['csv', 'json', 'yaml'], default='csv',
                       help='Output format (default: csv)')
    
    # Vulnerability database sources
    parser.add_argument('--enable-github-advisories', action='store_true', help='Enable GitHub Advisory Database')
    parser.add_argument('--enable-snyk', action='store_true', help='Enable Snyk vulnerability database')
    parser.add_argument('--enable-mitre', action='store_true', help='Enable MITRE CVE database')
    parser.add_argument('--enable-osv', action='store_true', help='Enable OSV (Open Source Vulnerabilities) database')
    parser.add_argument('--enable-all-sources', action='store_true', help='Enable all vulnerability sources')
    
    # API tokens for vulnerability databases
    parser.add_argument('--github-token', help='GitHub token for advisory access (or set GITHUB_TOKEN env var)')
    parser.add_argument('--snyk-token', help='Snyk API token (or set SNYK_TOKEN env var)')
    
    parser.add_argument('--verbose', '-v', action='store_true', help='Enable verbose logging')
    parser.add_argument('--version', action='version', version=f'%(prog)s {__version__}')
    
    args = parser.parse_args()
    
    # Use environment variables as fallback for optional tokens
    if not args.github_token:
        args.github_token = os.getenv('GITHUB_TOKEN')
    
    if not args.snyk_token:
        args.snyk_token = os.getenv('SNYK_TOKEN')
    
    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)
    
    # Set default URLs
    if not args.url:
        args.url = 'https://api.github.com' if args.provider == 'github' else 'https://gitlab.com'
    
    # Generate output filename if not provided
    if not args.output:
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        args.output = f"supply_chain_scan_{timestamp}.{args.format}"
    
    try:
        # Configure vulnerability sources
        vuln_sources = {
            'github': args.enable_github_advisories or args.enable_all_sources,
            'snyk': args.enable_snyk or args.enable_all_sources,
            'mitre': args.enable_mitre or args.enable_all_sources,
            'osv': args.enable_osv or args.enable_all_sources
        }
        
        # Use GitHub token for advisories if not separately provided  
        github_advisory_token = args.github_token or (args.token if args.provider == 'github' else None)
        
        # Load compromised packages
        compromised_packages = SupplyChainScanner.load_compromised_packages(
            args.packages, vuln_sources, github_advisory_token, args.snyk_token
        )
        logger.info(f"Loaded {len(compromised_packages)} compromised packages")
        
        # Create provider and scanner
        provider = SupplyChainScanner.create_provider(args.provider, args.url, args.token)
        scanner = SupplyChainScanner(provider, compromised_packages)
        
        # Perform scan
        vulnerabilities = scanner.scan_all_projects()
        
        # Export results
        scanner.export_results(vulnerabilities, args.output, args.format)
        
        # Print summary
        print(f"\n{'='*60}")
        print("SCAN COMPLETED")
        print(f"{'='*60}")
        print(f"Vulnerabilities found: {len(vulnerabilities)}")
        print(f"Report saved to: {args.output}")
        
        if vulnerabilities:
            print(f"\n⚠️  WARNING: {len(vulnerabilities)} supply chain threats found!")
            
            # Show summary by attack type
            attack_counts: Dict[str, int] = {}
            for vuln in vulnerabilities:
                attack_counts[vuln.attack_type] = attack_counts.get(vuln.attack_type, 0) + 1
            
            print(f"\nAttack types detected:")
            for attack_type, count in sorted(attack_counts.items(), key=lambda x: x[1], reverse=True):
                print(f"  - {attack_type}: {count} instances")
            
            # Show summary by project
            project_counts: Dict[str, int] = {}
            for vuln in vulnerabilities:
                project_counts[vuln.project] = project_counts.get(vuln.project, 0) + 1
            
            print(f"\nAffected projects:")
            for project, count in sorted(project_counts.items(), 
                                       key=lambda x: x[1], reverse=True)[:10]:
                print(f"  - {project}: {count} threats")
        else:
            print("✅ No supply chain threats detected in your repositories.")
        
        sys.exit(1 if vulnerabilities else 0)
        
    except Exception as e:
        logger.error(f"Scanner failed: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()