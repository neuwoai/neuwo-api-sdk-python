"""
Setup script for the Neuwo API SDK.

This file is kept for backwards compatibility with older build tools.
Modern configuration is in pyproject.toml.
"""

from setuptools import setup, find_packages
from pathlib import Path

# Read the README file
this_directory = Path(__file__).parent
long_description = (this_directory / "README.md").read_text(encoding="utf-8")

setup(
    name="neuwo_api",
    version="0.2.0",
    description="Neuwo API SDK - Python SDK client for the Neuwo content classification API.",
    long_description=long_description,
    author="Grzegorz Malisz",
    author_email="grzegorz.malisz@neuwo.ai",
    maintainer="Grzegorz Malisz",
    maintainer_email="grzegorz.malisz@neuwo.ai",
    long_description_content_type="text/markdown",
    url="https://neuwo.ai",
    project_urls={
        "Documentation": "https://docs.neuwo.ai",
        "Source": "https://github.com/neuwoai/neuwo-api-sdk-python",
    },
    packages=find_packages(exclude=["tests", "tests.*", "examples", "examples.*"]),
    include_package_data=True,
    python_requires=">=3.8",
    install_requires=[
        "requests>=2.25.0",
    ],
    extras_require={
        "dev": [
            "pytest>=7.0.0",
            "pytest-cov>=4.0.0",
            "black>=23.0.0",
            "flake8>=6.0.0",
            "mypy>=1.0.0",
            "isort>=5.12.0",
        ],
        "test": [
            "pytest>=7.0.0",
            "pytest-cov>=4.0.0",
            "responses>=0.23.0",
        ],
    },
    classifiers=[
        "Development Status :: 3 - Alpha",
        "Intended Audience :: Developers",
        "License :: OSI Approved :: MIT License",
        "Operating System :: OS Independent",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.8",
        "Programming Language :: Python :: 3.9",
        "Programming Language :: Python :: 3.10",
        "Programming Language :: Python :: 3.11",
        "Programming Language :: Python :: 3.12",
        "Topic :: Software Development :: Libraries :: Python Modules",
        "Topic :: Internet :: WWW/HTTP",
        "Typing :: Typed",
    ],
    keywords=[
        "neuwo",
        "api",
        "content-classification",
        "tagging",
        "ai",
        "machine-learning",
        "iab",
        "taxonomy",
        "brand-safety",
    ],
    license="MIT",
    zip_safe=False,
)
