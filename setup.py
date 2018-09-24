from setuptools import setup

with open("README.txt") as f:
    long_description = f.read()

setup(
    name="pyega3",
    description="EGA python client",
    long_description=long_description,
    packages=["pyega3"],
    version = "3.0.27",
    author="EGA team",
    author_email="ega-helpdesk@ebi.ac.uk",
    install_requires=["requests", "tqdm", "htsget"],
    keywords=["EGA", "archive"],
    license="Apache License, Version 2.0",
    url="https://github.com/EGA-archive/ega-download-client",
    classifiers=[        
        "Development Status :: 3 - Alpha",
        "Topic :: Scientific/Engineering :: Bio-Informatics",
        "License :: OSI Approved :: Apache Software License",
        "Programming Language :: Python :: 3.4"
    ],    
    entry_points={
            "console_scripts": [
                "pyega3 = pyega3.pyega3:main",
            ]
        }
)