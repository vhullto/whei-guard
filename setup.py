from setuptools import setup, find_packages
from pathlib import Path

setup(
    name="whei-guard",
    version="1.1.0",
    description="Enterprise AppSec Analyzer — Web2 (Semgrep) + Web3 (Slither) + Groq AI",
    long_description=(Path(__file__).parent / "README.md").read_text(encoding="utf-8")
        if (Path(__file__).parent / "README.md").exists() else "",
    python_requires=">=3.10",
    packages=find_packages(),
    py_modules=["whei", "whei_ai", "whei_report"],
    install_requires=[
        "slither-analyzer",   # motor Web3
        "semgrep",            # motor Web2
        "groq",               # cliente Groq AI
    ],
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