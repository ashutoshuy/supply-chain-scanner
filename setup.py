#!/usr/bin/env python3

from setuptools import setup, find_packages

with open("README.md", "r", encoding="utf-8") as fh:
    long_description = fh.read()

with open("requirements.txt", "r", encoding="utf-8") as fh:
    requirements = [line.strip() for line in fh if line.strip() and not line.startswith("#")]

setup(
    name="supply-chain-scanner",
    version="1.0.0",
    author="Security Community",
    author_email="security@community.org",
    description="A comprehensive security tool to detect compromised NPM packages in Git repositories",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/security-community/supply-chain-scanner",
    project_urls={
        "Bug Reports": "https://github.com/security-community/supply-chain-scanner/issues",
        "Source": "https://github.com/security-community/supply-chain-scanner",
        "Documentation": "https://github.com/security-community/supply-chain-scanner/wiki",
    },
    packages=find_packages(),
    classifiers=[
        "Development Status :: 5 - Production/Stable",
        "Intended Audience :: Developers",
        "Intended Audience :: System Administrators",
        "Topic :: Security",
        "Topic :: Software Development :: Quality Assurance",
        "Topic :: System :: Systems Administration",
        "License :: OSI Approved :: MIT License",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.7",
        "Programming Language :: Python :: 3.8",
        "Programming Language :: Python :: 3.9",
        "Programming Language :: Python :: 3.10",
        "Programming Language :: Python :: 3.11",
        "Operating System :: OS Independent",
    ],
    python_requires=">=3.7",
    install_requires=requirements,
    entry_points={
        "console_scripts": [
            "supply-chain-scanner=scanner:main",
            "scs=scanner:main",
        ],
    },
    keywords="security supply-chain npm vulnerability scanner github gitlab",
)