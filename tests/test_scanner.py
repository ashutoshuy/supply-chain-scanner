#!/usr/bin/env python3
"""
Unit tests for Supply Chain Security Scanner
"""

import pytest
import json
import tempfile
import os
from unittest.mock import Mock, patch, MagicMock
from scanner import (
    SupplyChainScanner, 
    GitLabProvider, 
    GitHubProvider, 
    Vulnerability
)


class TestSupplyChainScanner:
    
    def test_load_compromised_packages_from_txt_file(self):
        """Test loading packages from text file"""
        with tempfile.NamedTemporaryFile(mode='w', suffix='.txt', delete=False) as f:
            f.write("package1\n")
            f.write("# comment\n")
            f.write("package2\n")
            f.write("\n")  # empty line
            f.write("package3\n")
            temp_file = f.name
        
        try:
            packages = SupplyChainScanner.load_compromised_packages(temp_file)
            assert packages == ['package1', 'package2', 'package3']
        finally:
            os.unlink(temp_file)
    
    def test_load_compromised_packages_from_json_file(self):
        """Test loading packages from JSON file"""
        test_data = {
            "packages": ["pkg1", "pkg2", "pkg3"]
        }
        
        with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False) as f:
            json.dump(test_data, f)
            temp_file = f.name
        
        try:
            packages = SupplyChainScanner.load_compromised_packages(temp_file)
            assert packages == ["pkg1", "pkg2", "pkg3"]
        finally:
            os.unlink(temp_file)
    
    def test_load_default_packages(self):
        """Test loading default package list"""
        packages = SupplyChainScanner.load_compromised_packages()
        assert len(packages) > 0
        assert "@ctrl/tinycolor" in packages
        assert "ngx-toastr" in packages
    
    def test_create_gitlab_provider(self):
        """Test GitLab provider creation"""
        provider = SupplyChainScanner.create_provider(
            'gitlab', 'https://gitlab.com', 'test-token'
        )
        assert isinstance(provider, GitLabProvider)
    
    def test_create_github_provider(self):
        """Test GitHub provider creation"""
        provider = SupplyChainScanner.create_provider(
            'github', 'https://api.github.com', 'test-token'
        )
        assert isinstance(provider, GitHubProvider)
    
    def test_create_invalid_provider(self):
        """Test invalid provider raises error"""
        with pytest.raises(ValueError):
            SupplyChainScanner.create_provider(
                'invalid', 'https://example.com', 'token'
            )


class TestGitLabProvider:
    
    @patch('requests.Session.get')
    def test_gitlab_auth_setup(self, mock_get):
        """Test GitLab authentication header setup"""
        provider = GitLabProvider('https://gitlab.com', 'test-token')
        assert provider.session.headers['PRIVATE-TOKEN'] == 'test-token'
    
    @patch('requests.Session.get')
    def test_gitlab_get_projects(self, mock_get):
        """Test GitLab project fetching"""
        # Mock API response
        mock_response = Mock()
        mock_response.json.return_value = [
            {'id': 1, 'path_with_namespace': 'group/project1'},
            {'id': 2, 'path_with_namespace': 'group/project2'}
        ]
        mock_response.raise_for_status.return_value = None
        mock_get.return_value = mock_response
        
        provider = GitLabProvider('https://gitlab.com', 'test-token')
        
        # Mock empty response to stop pagination
        mock_response.json.side_effect = [
            [{'id': 1, 'path_with_namespace': 'group/project1'}],
            []  # Empty response to end pagination
        ]
        
        projects = provider.get_projects()
        assert len(projects) == 1
        assert projects[0]['id'] == 1
    
    @patch('requests.Session.get')
    def test_gitlab_get_package_files(self, mock_get):
        """Test finding package.json files in GitLab project"""
        mock_response = Mock()
        mock_response.json.return_value = [
            {'path': 'package.json', 'name': 'package.json', 'type': 'blob'},
            {'path': 'frontend/package.json', 'name': 'package.json', 'type': 'blob'},
            {'path': 'README.md', 'name': 'README.md', 'type': 'blob'}
        ]
        mock_response.raise_for_status.return_value = None
        mock_get.return_value = mock_response
        
        provider = GitLabProvider('https://gitlab.com', 'test-token')
        files = provider.get_package_files(123)
        
        assert len(files) == 2
        assert 'package.json' in files
        assert 'frontend/package.json' in files
    
    @patch('requests.Session.get')
    def test_gitlab_get_file_content(self, mock_get):
        """Test reading package.json content from GitLab"""
        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.text = '{"dependencies": {"lodash": "^4.17.21"}}'
        mock_get.return_value = mock_response
        
        provider = GitLabProvider('https://gitlab.com', 'test-token')
        content = provider.get_file_content(123, 'package.json')
        
        assert content is not None
        assert 'dependencies' in content
        assert content['dependencies']['lodash'] == '^4.17.21'


class TestGitHubProvider:
    
    @patch('requests.Session.get')
    def test_github_auth_setup(self, mock_get):
        """Test GitHub authentication header setup"""
        provider = GitHubProvider('https://api.github.com', 'test-token')
        assert provider.session.headers['Authorization'] == 'token test-token'
        assert provider.session.headers['Accept'] == 'application/vnd.github.v3+json'
    
    @patch('requests.Session.get')
    def test_github_get_projects(self, mock_get):
        """Test GitHub repository fetching"""
        mock_response = Mock()
        mock_response.json.return_value = [
            {
                'id': 1, 
                'name': 'repo1', 
                'full_name': 'user/repo1',
                'html_url': 'https://github.com/user/repo1'
            }
        ]
        mock_response.raise_for_status.return_value = None
        mock_get.return_value = mock_response
        
        # Mock empty response to stop pagination
        mock_response.json.side_effect = [
            [{
                'id': 1, 
                'name': 'repo1', 
                'full_name': 'user/repo1',
                'html_url': 'https://github.com/user/repo1'
            }],
            []
        ]
        
        provider = GitHubProvider('https://api.github.com', 'test-token')
        projects = provider.get_projects()
        
        assert len(projects) == 1
        assert projects[0]['id'] == 1
        assert projects[0]['path_with_namespace'] == 'user/repo1'


class TestVulnerability:
    
    def test_vulnerability_creation(self):
        """Test Vulnerability dataclass creation"""
        vuln = Vulnerability(
            project="test/project",
            project_id=123,
            package="lodash",
            version="4.17.20",
            file_path="package.json",
            dependency_type="dependencies",
            risk_level="CRITICAL"
        )
        
        assert vuln.project == "test/project"
        assert vuln.package == "lodash"
        assert vuln.scan_timestamp is not None
    
    def test_vulnerability_with_timestamp(self):
        """Test Vulnerability with custom timestamp"""
        custom_timestamp = "2025-09-17T14:30:00"
        vuln = Vulnerability(
            project="test/project",
            project_id=123,
            package="lodash",
            version="4.17.20",
            file_path="package.json",
            dependency_type="dependencies",
            risk_level="CRITICAL",
            scan_timestamp=custom_timestamp
        )
        
        assert vuln.scan_timestamp == custom_timestamp


class TestScannerIntegration:
    
    def test_scan_project_with_vulnerability(self):
        """Test scanning project that contains vulnerabilities"""
        # Mock provider
        mock_provider = Mock()
        mock_provider.get_package_files.return_value = ['package.json']
        mock_provider.get_file_content.return_value = {
            'dependencies': {
                '@ctrl/tinycolor': '^4.1.1',
                'lodash': '^4.17.21'
            }
        }
        
        # Mock project data
        project = {
            'id': 123,
            'path_with_namespace': 'test/project',
            'web_url': 'https://gitlab.com/test/project'
        }
        
        scanner = SupplyChainScanner(mock_provider, ['@ctrl/tinycolor'])
        vulnerabilities = scanner.scan_project(project)
        
        assert len(vulnerabilities) == 1
        assert vulnerabilities[0].package == '@ctrl/tinycolor'
        assert vulnerabilities[0].version == '^4.1.1'
        assert vulnerabilities[0].risk_level == 'CRITICAL'
    
    def test_scan_project_without_vulnerability(self):
        """Test scanning project with no vulnerabilities"""
        mock_provider = Mock()
        mock_provider.get_package_files.return_value = ['package.json']
        mock_provider.get_file_content.return_value = {
            'dependencies': {
                'lodash': '^4.17.21',
                'axios': '^0.24.0'
            }
        }
        
        project = {
            'id': 123,
            'path_with_namespace': 'test/project',
            'web_url': 'https://gitlab.com/test/project'
        }
        
        scanner = SupplyChainScanner(mock_provider, ['@ctrl/tinycolor'])
        vulnerabilities = scanner.scan_project(project)
        
        assert len(vulnerabilities) == 0
    
    def test_export_results_csv(self):
        """Test exporting results to CSV format"""
        mock_provider = Mock()
        scanner = SupplyChainScanner(mock_provider, [])
        
        vulnerabilities = [
            Vulnerability(
                project="test/project",
                project_id=123,
                package="@ctrl/tinycolor",
                version="^4.1.1",
                file_path="package.json",
                dependency_type="dependencies",
                risk_level="CRITICAL"
            )
        ]
        
        with tempfile.NamedTemporaryFile(mode='w', suffix='.csv', delete=False) as f:
            temp_file = f.name
        
        try:
            scanner.export_results(vulnerabilities, temp_file, 'csv')
            
            # Verify CSV was created and has content
            assert os.path.exists(temp_file)
            with open(temp_file, 'r') as f:
                content = f.read()
                assert 'project,project_id,package' in content
                assert '@ctrl/tinycolor' in content
        finally:
            os.unlink(temp_file)
    
    def test_export_results_json(self):
        """Test exporting results to JSON format"""
        mock_provider = Mock()
        scanner = SupplyChainScanner(mock_provider, [])
        
        vulnerabilities = [
            Vulnerability(
                project="test/project",
                project_id=123,
                package="@ctrl/tinycolor",
                version="^4.1.1",
                file_path="package.json",
                dependency_type="dependencies",
                risk_level="CRITICAL"
            )
        ]
        
        with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False) as f:
            temp_file = f.name
        
        try:
            scanner.export_results(vulnerabilities, temp_file, 'json')
            
            # Verify JSON was created and has correct structure
            assert os.path.exists(temp_file)
            with open(temp_file, 'r') as f:
                data = json.load(f)
                assert 'scan_info' in data
                assert 'vulnerabilities' in data
                assert len(data['vulnerabilities']) == 1
                assert data['vulnerabilities'][0]['package'] == '@ctrl/tinycolor'
        finally:
            os.unlink(temp_file)


if __name__ == '__main__':
    pytest.main([__file__])