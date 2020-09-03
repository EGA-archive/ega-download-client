from setuptools import setup, find_packages

with open("README.md", encoding='utf-8') as f:
    long_description = f.read()

setup(
    name="pyega3",
    description="EGA python client",
    long_description=long_description,
    long_description_content_type="text/plain",
    packages=find_packages(),
    version = "3.3.0",
    author="EGA team",
    author_email="ega-helpdesk@ebi.ac.uk",
    install_requires=["requests", "tqdm", "htsget", "psutil"],
    keywords=["EGA", "archive"],
    license="Apache License, Version 2.0",
    url="https://github.com/EGA-archive/ega-download-client",
    include_package_data=True,
    classifiers=[
        "Development Status :: 3 - Alpha",
        "Topic :: Scientific/Engineering :: Bio-Informatics",
        "License :: OSI Approved :: Apache Software License",
        "Programming Language :: Python :: 3.5"
    ],    
    entry_points={
            "console_scripts": [
                "pyega3 = pyega3.pyega3:main",
            ]
        }
)
