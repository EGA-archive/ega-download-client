import sys

from setuptools import setup, find_packages

CURRENT_PYTHON_VERSION = sys.version_info[:2]

# When changing the value of the REQUIRED_PYTHON_VERSION variable,
# make sure to also change the "python_requires" variable
# and the "classifiers" section in this file (setup.py).
REQUIRED_PYTHON_VERSION = (3, 6)

if CURRENT_PYTHON_VERSION < REQUIRED_PYTHON_VERSION:
    sys.stderr.write("""
==========================
Unsupported Python version
==========================
This version of pyEGA3 requires Python {}.{}, but you're trying to
install it on Python {}.{}. Please try to upgrade to a newer Python
version or maybe use pyEGA3 in a Docker container (see the README for that).
""".format(*(REQUIRED_PYTHON_VERSION + CURRENT_PYTHON_VERSION)))
    sys.exit(1)

with open("README.md", encoding='utf-8') as f:
    long_description = f.read()

setup(
    name="pyega3",
    description="EGA python client",
    long_description=long_description,
    long_description_content_type="text/plain",
    packages=find_packages(),
    version="4.0.0",
    author="EGA team",
    author_email="ega-helpdesk@ebi.ac.uk",
    python_requires=">=3.6",
    install_requires=["requests==2.26.0", "tqdm==4.19.6", "htsget==0.2.5", "psutil==5.6.6", "urllib3==1.26.7"],
    tests_require=["pytest~=6.2.5", "coverage==4.5.1", "responses~=0.16.0", "pyfakefs~=4.5.3"],
    keywords=["EGA", "archive"],
    license="Apache License, Version 2.0",
    url="https://github.com/EGA-archive/ega-download-client",
    include_package_data=True,
    classifiers=[
        "Development Status :: 3 - Alpha",
        "Topic :: Scientific/Engineering :: Bio-Informatics",
        "License :: OSI Approved :: Apache Software License",
        "Programming Language :: Python :: 3.6"
    ],
    entry_points={
        "console_scripts": [
            "pyega3 = pyega3.pyega3:main",
        ]
    }
)
