from setuptools import setup

with open("README") as f:
    long_description = f.read()

setup(
    name="pyega3",
    description="EGA python client",
    long_description=long_description,
    packages=["pyega3"],
    version = "3.0.15",
    author="EGA team",
    author_email="ega-helpdesk@ebi.ac.uk",
    install_requires=["requests", "tqdm"],
    keywords=["EGA", "archive"],
    entry_points={
            'console_scripts': [
                'pyega3 = pyega3.pyega3:main',
            ]
        }
)