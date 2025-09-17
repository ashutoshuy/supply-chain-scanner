# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added
- Initial open source release
- Multi-platform Git provider support (GitHub, GitLab)
- Multiple output formats (CSV, JSON, YAML)
- Comprehensive test suite
- Docker containerization
- CI/CD pipeline with GitHub Actions
- Extensive documentation and examples

### Security
- Secure token handling
- HTTPS-only API communications
- No credential storage
- Minimal data collection

## [1.0.0] - 2025-09-17

### Added
- **Core Features**
  - Supply chain vulnerability scanning for NPM packages
  - Support for GitLab and GitHub repositories
  - Configurable compromised package lists
  - Multiple export formats (CSV, JSON, YAML)
  - Comprehensive logging and error handling

- **Git Provider Support**
  - GitLab.com and self-hosted GitLab instances
  - GitHub.com and GitHub Enterprise
  - Automatic pagination for large repository sets
  - Robust API error handling and rate limiting

- **Security Features**
  - Default Shai-Hulud attack package detection
  - Custom package list support (TXT and JSON formats)
  - Risk level assessment (CRITICAL for known compromised packages)
  - Detailed vulnerability reporting with project context

- **Developer Experience**
  - Command-line interface with comprehensive help
  - Verbose logging mode for debugging
  - Progress tracking for large scans
  - Automatic output file naming with timestamps

- **Integration Support**
  - Docker containerization for easy deployment
  - CI/CD pipeline templates for GitLab and GitHub
  - Python package distribution via PyPI
  - Comprehensive documentation and examples

- **Quality Assurance**
  - Full test suite with pytest
  - Code quality tools (Black, Flake8, MyPy, Bandit)
  - Type hints throughout codebase
  - Security scanning with Bandit

### Technical Details
- **Supported Python Versions**: 3.7, 3.8, 3.9, 3.10, 3.11
- **Dependencies**: requests, PyYAML, urllib3
- **License**: MIT License
- **Package Size**: Minimal dependencies for fast installation

### Known Limitations
- Currently supports only NPM package.json files
- Bitbucket support planned for future release
- No real-time monitoring capabilities yet
- Limited to dependency and devDependency sections

### Breaking Changes
- None (initial release)

### Migration Guide
- None (initial release)

---

## Release Notes Template

### [Version] - YYYY-MM-DD

#### Added
- New features and capabilities

#### Changed
- Changes to existing functionality

#### Deprecated
- Features marked for removal in future versions

#### Removed
- Features removed in this version

#### Fixed
- Bug fixes and corrections

#### Security
- Security-related changes and improvements