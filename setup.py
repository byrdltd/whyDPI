"""
Setup script for whyDPI
"""

from setuptools import setup, find_packages

with open("README.md", "r", encoding="utf-8") as f:
    long_description = f.read()

setup(
    name="whydpi",
    version="0.1.0",
    author="whyDPI Contributors",
    description="Educational DPI bypass tool for research purposes",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/byrdltd/whyDPI",
    packages=find_packages(),
    classifiers=[
        "Development Status :: 3 - Alpha",
        "Intended Audience :: Education",
        "Intended Audience :: Developers",
        "Intended Audience :: Science/Research",
        "Topic :: Education",
        "Topic :: Security",
        "Topic :: System :: Networking",
        "License :: OSI Approved :: MIT License",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.8",
        "Programming Language :: Python :: 3.9",
        "Programming Language :: Python :: 3.10",
        "Programming Language :: Python :: 3.11",
        "Operating System :: POSIX :: Linux",
    ],
    python_requires=">=3.8",
    install_requires=[
        "NetfilterQueue>=1.1.0",
        "scapy>=2.5.0",
    ],
    entry_points={
        "console_scripts": [
            "whydpi=whydpi.__main__:main",
        ],
    },
)
