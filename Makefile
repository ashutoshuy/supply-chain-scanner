.PHONY: help install test lint format clean build docker

help:
	@echo "Available commands:"
	@echo "  install     Install dependencies"
	@echo "  test        Run tests"
	@echo "  lint        Run linting"
	@echo "  format      Format code"
	@echo "  clean       Clean build artifacts"
	@echo "  build       Build package"
	@echo "  docker      Build Docker image"

install:
	pip install -r requirements.txt
	pip install -r requirements-dev.txt

test:
	pytest tests/ --cov=scanner --cov-report=html --cov-report=term

lint:
	flake8 scanner.py tests/
	mypy scanner.py --ignore-missing-imports
	bandit -r scanner.py

format:
	black scanner.py tests/
	isort scanner.py tests/

clean:
	rm -rf build/
	rm -rf dist/
	rm -rf *.egg-info/
	rm -rf htmlcov/
	rm -rf .pytest_cache/
	rm -rf .coverage
	find . -type d -name __pycache__ -exec rm -rf {} +
	find . -type f -name "*.pyc" -delete

build: clean
	python -m build

docker:
	docker build -t supply-chain-scanner:latest .

# Development shortcuts
dev-scan-gitlab:
	python scanner.py --provider gitlab --token $(GITLAB_TOKEN) --verbose

dev-scan-github:
	python scanner.py --provider github --token $(GITHUB_TOKEN) --verbose