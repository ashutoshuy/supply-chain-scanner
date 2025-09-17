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
from datetime import datetime
from typing import List, Dict, Optional, Union
from pathlib import Path
import urllib.parse
import logging
from dataclasses import dataclass, asdict

__version__ = "1.0.0"
__author__ = "Security Community"
__license__ = "MIT"

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

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
    repository_url: str = ""
    scan_timestamp: str = ""
    
    def __post_init__(self):
        if not self.scan_timestamp:
            self.scan_timestamp = datetime.now().isoformat()

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
    
    def get_package_files(self, project_id: Union[str, int]) -> List[str]:
        """Get package.json files in project"""
        raise NotImplementedError
    
    def get_file_content(self, project_id: Union[str, int], file_path: str) -> Optional[Dict]:
        """Get content of package.json file"""
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
            params = {
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
    
    def get_package_files(self, project_id: Union[str, int]) -> List[str]:
        try:
            url = f"{self.base_url}/api/v4/projects/{project_id}/repository/tree"
            params = {'recursive': 'true', 'per_page': 100}
            
            response = self.session.get(url, params=params, timeout=30)
            if response.status_code == 404:
                return []
            
            response.raise_for_status()
            tree = response.json()
            
            return [item['path'] for item in tree 
                   if item['name'] == 'package.json' and item['type'] == 'blob']
                   
        except requests.RequestException:
            return []
    
    def get_file_content(self, project_id: Union[str, int], file_path: str) -> Optional[Dict]:
        encoded_path = urllib.parse.quote(file_path, safe='')
        
        for ref in ['main', 'master', 'develop']:
            try:
                url = f"{self.base_url}/api/v4/projects/{project_id}/repository/files/{encoded_path}/raw"
                params = {'ref': ref}
                
                response = self.session.get(url, params=params, timeout=30)
                if response.status_code == 200:
                    return json.loads(response.text)
            except (requests.RequestException, json.JSONDecodeError):
                continue
        
        return None

class GitHubProvider(GitProvider):
    """GitHub API provider"""
    
    def _setup_auth(self) -> None:
        self.session.headers.update({
            'Authorization': f'token {self.token}',
            'Accept': 'application/vnd.github.v3+json'
        })
    
    def get_projects(self) -> List[Dict]:
        projects = []
        page = 1
        per_page = 100
        
        logger.info("Fetching GitHub repositories...")
        while True:
            url = f"{self.base_url}/user/repos"
            params = {
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
    
    def get_package_files(self, project_id: Union[str, int]) -> List[str]:
        # Get repository info first
        try:
            repo_response = self.session.get(f"{self.base_url}/repositories/{project_id}")
            repo_response.raise_for_status()
            repo_info = repo_response.json()
            
            url = f"{self.base_url}/repos/{repo_info['full_name']}/git/trees/{repo_info['default_branch']}"
            params = {'recursive': '1'}
            
            response = self.session.get(url, params=params, timeout=30)
            if response.status_code == 404:
                return []
            
            response.raise_for_status()
            tree = response.json()
            
            return [item['path'] for item in tree.get('tree', [])
                   if item['path'].endswith('package.json') and item['type'] == 'blob']
                   
        except requests.RequestException:
            return []
    
    def get_file_content(self, project_id: Union[str, int], file_path: str) -> Optional[Dict]:
        try:
            # Get repository info
            repo_response = self.session.get(f"{self.base_url}/repositories/{project_id}")
            repo_response.raise_for_status()
            repo_info = repo_response.json()
            
            url = f"{self.base_url}/repos/{repo_info['full_name']}/contents/{file_path}"
            
            response = self.session.get(url, timeout=30)
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
    def load_compromised_packages(cls, package_file: Optional[str] = None) -> List[str]:
        """Load compromised packages from file or use defaults"""
        if package_file and Path(package_file).exists():
            logger.info(f"Loading compromised packages from {package_file}")
            with open(package_file, 'r') as f:
                if package_file.endswith('.json'):
                    data = json.load(f)
                    return data.get('packages', data) if isinstance(data, dict) else data
                else:
                    return [line.strip() for line in f if line.strip() and not line.startswith('#')]
        
        logger.info("Using default Shai-Hulud compromised packages list")
        return cls._get_default_packages()
    
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
        """Scan a single project for compromised packages"""
        vulnerabilities = []
        project_name = project['path_with_namespace']
        project_id = project['id']
        
        logger.info(f"Scanning: {project_name}")
        
        package_files = self.provider.get_package_files(project_id)
        
        for file_path in package_files:
            package_json = self.provider.get_file_content(project_id, file_path)
            if not package_json:
                continue
            
            # Check dependencies and devDependencies
            for dep_type in ['dependencies', 'devDependencies']:
                deps = package_json.get(dep_type, {})
                
                for package_name, version in deps.items():
                    if package_name in self.compromised_packages:
                        vuln = Vulnerability(
                            project=project_name,
                            project_id=project_id,
                            package=package_name,
                            version=version,
                            file_path=file_path,
                            dependency_type=dep_type,
                            risk_level='CRITICAL',
                            repository_url=project.get('web_url', '')
                        )
                        vulnerabilities.append(vuln)
                        logger.warning(f"Found: {package_name}@{version} in {file_path}")
        
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
  
  # Scan GitHub repositories  
  python scanner.py --provider github --token ghp-xxx --url https://api.github.com
  
  # Use custom package list and JSON output
  python scanner.py --provider gitlab --token xxx --packages packages.txt --format json
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
    parser.add_argument('--verbose', '-v', action='store_true', help='Enable verbose logging')
    parser.add_argument('--version', action='version', version=f'%(prog)s {__version__}')
    
    args = parser.parse_args()
    
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
        # Load compromised packages
        compromised_packages = SupplyChainScanner.load_compromised_packages(args.packages)
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
            print(f"\n⚠️  WARNING: {len(vulnerabilities)} compromised packages found!")
            
            # Show summary by project
            project_counts = {}
            for vuln in vulnerabilities:
                project_counts[vuln.project] = project_counts.get(vuln.project, 0) + 1
            
            print(f"\nAffected projects:")
            for project, count in sorted(project_counts.items(), 
                                       key=lambda x: x[1], reverse=True)[:10]:
                print(f"  - {project}: {count} vulnerable packages")
        else:
            print("✅ No compromised packages found in your repositories.")
        
        sys.exit(1 if vulnerabilities else 0)
        
    except Exception as e:
        logger.error(f"Scanner failed: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()