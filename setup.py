"""Setup script for OSINTRecon."""

from pathlib import Path
from setuptools import setup, find_packages

here = Path(__file__).parent
long_description = (here / "README.md").read_text(encoding="utf-8")

setup(
    name="osintrecon",
    version="1.0.0",
    author="kadirou12333",
    description="Lightweight OSINT reconnaissance framework for CTF competitions",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/kadirou12333/osint-recon-framework",
    packages=find_packages(),
    include_package_data=True,
    package_data={
        "osintrecon": ["data/*.json"],
    },
    python_requires=">=3.10",
    install_requires=[
        "httpx>=0.25.0",
        "rich>=13.0.0",
        "Pillow>=10.0.0",
        "dnspython>=2.4.0",
        "pydantic>=2.0.0",
        "python-whois>=0.9.0",
    ],
    extras_require={
        "dev": [
            "pytest>=7.0.0",
            "pytest-asyncio>=0.23.0",
        ],
    },
    entry_points={
        "console_scripts": [
            "osintrecon=cli:main",
        ],
    },
    classifiers=[
        "Development Status :: 4 - Beta",
        "Intended Audience :: Developers",
        "Intended Audience :: Information Technology",
        "License :: OSI Approved :: MIT License",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.10",
        "Programming Language :: Python :: 3.11",
        "Programming Language :: Python :: 3.12",
        "Topic :: Security",
    ],
    keywords="osint reconnaissance ctf security username-lookup domain-recon",
)
