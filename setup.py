from setuptools import setup

with open("README.md") as f:
    readme = f.read()

setup(
    name="pwnAD",
    version="0.0.1",
    license="MIT",
    author="LightxR",
    url="https://github.com/LightxR/ADL",
    long_description=readme,
    long_description_content_type="text/markdown",
    install_requires=[
        "asn1crypto",
        "cryptography>=39.0",
        "impacket",
        "ldap3-bleeding-edge",
        "pyasn1==0.4.8",
        "dsinternals",
    ],
    packages=[
        "pwnAD",
        "pwnAD.commands",
        "pwnAD.lib",
    ],
    entry_points={
        "console_scripts": ["pwnAD=pwnAD.main:main"],
    },
    description="Active Directory enumeration and abuse",
)
