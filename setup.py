from setuptools import setup, find_packages
from pathlib import Path

setup(
    name="whei-guard",
    version="2.0.0",
    description="Bug Bounty Platform — Recon + Web2/Web3 SAST + Groq/Anthropic/DeepSeek AI",
    long_description=(Path(__file__).parent / "README.md").read_text(encoding="utf-8")
        if (Path(__file__).parent / "README.md").exists() else "",
    python_requires=">=3.10",
    packages=find_packages(),
    py_modules=["whei", "whei_ai", "whei_report", "whei_recon", "whei_web", "whei_scan_active"],
    install_requires=[
        "slither-analyzer",   # motor Web3 (Slither)
        "semgrep",            # motor Web2 (Semgrep)
        "groq",               # cliente Groq AI
        "requests",           # HTTP para recon + DeepSeek API
        "flask",              # web dashboard
        "pyyaml",             # config.yaml support
    ],
    extras_require={
        "anthropic": ["anthropic"],           # Anthropic Claude provider
        "all": ["anthropic"],                 # todos os providers opcionais
    },
    entry_points={
        "console_scripts": [
            "whei=whei:main",
        ],
    },
    classifiers=[
        "Programming Language :: Python :: 3",
        "Topic :: Security",
    ],
)