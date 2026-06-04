#!/usr/bin/env python3
"""Setup script for ReconForge."""

from setuptools import setup, find_packages

setup(
    name="reconforge",
    version="1.0.0",
    description="Automated Cyber Reconnaissance Framework",
    long_description=open("README.md").read(),
    long_description_content_type="text/markdown",
    author="godes",
    url="https://github.com/godes/reconforge",
    packages=find_packages(include=["reconforge", "reconforge.*"]),
    install_requires=[
        "rich>=13.0",
        "dnspython>=2.0",
    ],
    entry_points={
        "console_scripts": [
            "reconforge=reconforge.__main__:main",
        ],
    },
    python_requires=">=3.8",
    classifiers=[
        "Development Status :: 4 - Beta",
        "Intended Audience :: Information Technology",
        "License :: OSI Approved :: MIT License",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.8",
        "Programming Language :: Python :: 3.9",
        "Programming Language :: Python :: 3.10",
        "Programming Language :: Python :: 3.11",
        "Topic :: Security",
        "Topic :: Internet",
    ],
)
