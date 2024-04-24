import pip
from setuptools import setup, find_packages
from homelink_python import __version__

setup(
    name="homelinkpython",
    version=__version__,
    description="Python Implementation of the HomeLink Client",
    url="https://github.com/jonathanadotey77/HomeLinkPython",
    author="Jonathan Adotey",
    packages=find_packages(),
    entry_points={
        "console_scripts" : [
            "homelink_python_cli=homelink_python.cli:main"
        ]
    },
    classifiers=[
        "Intended Audience :: Developers",

        "Programming Language :: Python",
        "Programming Language :: Python :: 3",
    ],
    install_requires=[
        "pycryptodome"
    ],
)
