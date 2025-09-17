# Contributing to Supply Chain Security Scanner

Thank you for your interest in contributing to this project! Your contributions help make the software development ecosystem more secure.

## Ways to Contribute

### 🐛 Bug Reports
- Use GitHub Issues to report bugs
- Include detailed reproduction steps
- Provide environment details (Python version, OS, etc.)
- Include relevant logs or error messages

### ✨ Feature Requests  
- Describe the problem you're trying to solve
- Explain why the feature would be valuable
- Consider implementation approaches
- Check existing issues to avoid duplicates

### 🛠️ Code Contributions
- Fork the repository
- Create a feature branch
- Write clean, documented code
- Include tests for new functionality
- Submit a pull request

### 📚 Documentation
- Improve README clarity
- Add usage examples
- Fix typos or outdated information
- Create tutorials or guides

## Development Setup

### Prerequisites
- Python 3.8+
- Git
- GitHub or GitLab account for testing

### Local Setup
```bash
# Clone your fork
git clone https://github.com/yourusername/supply-chain-scanner.git
cd supply-chain-scanner

# Install dependencies
pip install -r requirements.txt
pip install -r requirements-dev.txt

# Install pre-commit hooks
pre-commit install
```

### Running Tests
```bash
# Run all tests
pytest

# Run with coverage
pytest --cov=scanner --cov-report=html

# Run specific test file
pytest tests/test_providers.py
```

### Code Style
We use the following tools for code quality:
- **Black**: Code formatting
- **Flake8**: Linting
- **MyPy**: Type checking
- **Bandit**: Security scanning

```bash
# Format code
black scanner.py

# Check linting
flake8 scanner.py

# Type checking
mypy scanner.py --ignore-missing-imports

# Security scan
bandit -r scanner.py
```

## Contribution Guidelines

### Code Standards
1. **Type Hints**: Use type hints for all function parameters and return values
2. **Docstrings**: Include docstrings for all public methods
3. **Error Handling**: Handle exceptions gracefully with appropriate logging
4. **Testing**: Write tests for new features and bug fixes
5. **Performance**: Consider performance implications of changes

### Git Workflow
1. Create descriptive branch names (`feature/github-enterprise`, `fix/timeout-handling`)
2. Write clear commit messages
3. Keep commits focused and atomic
4. Rebase before submitting PR to maintain clean history

### Pull Request Process
1. Ensure all tests pass
2. Update documentation as needed
3. Add entry to CHANGELOG.md
4. Request review from maintainers
5. Address feedback promptly

## Priority Areas

### High Priority
- **New Git Providers**: Bitbucket, Azure DevOps, SourceForge
- **Package Manager Support**: PyPI, RubyGems, Maven, NuGet
- **Performance Improvements**: Async operations, caching
- **Enterprise Features**: SSO integration, audit logging

### Medium Priority
- **Output Formats**: HTML reports, PDF generation
- **Integrations**: Slack notifications, JIRA tickets
- **CI/CD Templates**: More platform examples
- **Monitoring**: Health checks, metrics collection

### Low Priority
- **UI Development**: Web interface
- **Mobile Support**: React Native, Cordova scanning
- **Historical Analysis**: Trend tracking, regression detection

## Architecture Guidelines

### Adding New Providers
1. Inherit from `GitProvider` base class
2. Implement required methods:
   - `_setup_auth()`
   - `get_projects()`
   - `get_package_files()`
   - `get_file_content()`
3. Add comprehensive error handling
4. Include provider-specific tests
5. Update documentation

### Provider Implementation Example
```python
class NewProvider(GitProvider):
    def _setup_auth(self):
        self.session.headers.update({
            'Authorization': f'Bearer {self.token}'
        })
    
    def get_projects(self) -> List[Dict]:
        # Implementation
        pass
```

### Testing New Providers
```python
def test_new_provider_auth():
    provider = NewProvider("https://api.example.com", "test-token")
    assert "Authorization" in provider.session.headers

def test_new_provider_projects():
    # Mock API responses and test project fetching
    pass
```

## Security Considerations

### Token Handling
- Never log or print API tokens
- Use environment variables for testing
- Implement token validation
- Support token rotation

### API Rate Limiting
- Respect provider rate limits
- Implement exponential backoff
- Add configurable delays
- Monitor rate limit headers

### Data Privacy
- Minimize data collection
- Don't store sensitive information
- Use HTTPS for all API calls
- Follow GDPR/privacy requirements

## Release Process

### Version Numbers
We use semantic versioning (MAJOR.MINOR.PATCH):
- **MAJOR**: Breaking API changes
- **MINOR**: New features, backward compatible
- **PATCH**: Bug fixes, security patches

### Release Checklist
1. Update version in `setup.py` and `scanner.py`
2. Update CHANGELOG.md with release notes
3. Run full test suite
4. Create Git tag
5. Update documentation
6. Publish to PyPI
7. Create GitHub release

## Community

### Communication
- **GitHub Discussions**: General questions and ideas
- **GitHub Issues**: Bug reports and feature requests  
- **Discord**: Real-time community chat (coming soon)
- **Twitter**: @SupplyChainSec for announcements

### Code of Conduct
We follow the [Contributor Covenant](https://www.contributor-covenant.org/):
- Be respectful and inclusive
- Welcome newcomers and help them learn
- Focus on constructive feedback
- Respect different viewpoints and experiences

### Recognition
Contributors are recognized in:
- CONTRIBUTORS.md file
- Release notes for their contributions
- Special badges for significant contributions
- Conference speaking opportunities

## Getting Help

### For Contributors
- Check existing issues and documentation first
- Ask questions in GitHub Discussions
- Tag maintainers for urgent security issues
- Join our Discord for real-time help

### For Maintainers
- Review PRs within 48 hours
- Provide constructive feedback
- Help with testing and deployment
- Mentor new contributors

## FAQ

**Q: How do I add support for a new package manager?**
A: Start by studying the existing NPM implementation, then create a new scanner class following the same patterns.

**Q: Can I contribute if I'm new to security?**
A: Absolutely! Start with documentation improvements or small bug fixes to get familiar with the codebase.

**Q: How do I test my changes with real repositories?**
A: Use test repositories with known vulnerable packages, or create sample projects for testing.

**Q: What if I find a security vulnerability in the scanner itself?**
A: Please report security issues privately to security@community.org rather than creating public issues.

Thank you for helping make software supply chains more secure!