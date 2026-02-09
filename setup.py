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
        #"ldap3-bleeding-edge",
        "ldap3==2.10.2rc3",
        "pyasn1==0.4.8",
        "dsinternals",
        "flask",
        "waitress",
    ],
    packages=[
        "pwnAD",
        "pwnAD.commands",
        "pwnAD.lib",
        "pwnAD.web",
        "pwnAD.web.routes",
    ],
    package_data={
        "pwnAD.web": ["templates/*.html", "templates/partials/*.html", "static/*"],
    },
    entry_points={
        "console_scripts": ["pwnAD=pwnAD.main:main"],
    },
    description="Active Directory enumeration and abuse",
)
