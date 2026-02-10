"""
Setup script for zkNIDS Phase 2 package
"""

from setuptools import setup, find_packages
from pathlib import Path

# Read README
readme_file = Path(__file__).parent / 'README.md'
long_description = readme_file.read_text() if readme_file.exists() else ''

setup(
    name='zkNIDS-phase2',
    version='0.1.0',
    description='zkNIDS Phase 2 - Local Detection & Invariants Engine',
    long_description=long_description,
    long_description_content_type='text/markdown',
    author='zkNIDS Project',
    python_requires='>=3.8',
    
    packages=find_packages(),
    include_package_data=True,
    
    install_requires=[
        'pyyaml>=6.0',
    ],
    
    extras_require={
        'dev': [
            'pytest>=7.0',
            'pytest-cov>=3.0',
        ],
    },
    
    entry_points={
        'console_scripts': [
            'phase2-detector=zkNIDS_phase2.__main__:main',
        ],
    },
    
    classifiers=[
        'Development Status :: 3 - Alpha',
        'Intended Audience :: System Administrators',
        'Intended Audience :: Information Technology',
        'Topic :: Security',
        'Topic :: System :: Monitoring',
        'Programming Language :: Python :: 3',
        'Programming Language :: Python :: 3.8',
        'Programming Language :: Python :: 3.9',
        'Programming Language :: Python :: 3.10',
        'Programming Language :: Python :: 3.11',
    ],
    
    project_urls={
        'Source': 'https://github.com/zkNIDS/zkNIDS',
        'Documentation': 'https://zkNIDS.readthedocs.io',
    },
)