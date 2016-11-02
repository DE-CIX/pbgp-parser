from setuptools import setup, find_packages

with open('requirements.txt', 'r') as f:
    requirements = f.readlines()
packages = ['pbgpp.' + pkg for pkg in find_packages('pbgpp')]
packages.append('pbgpp')

setup(
    name='pbgpp',
    version='0.2.0',
    description='PCAP BGP Parser',
    author='DE-CIX Management GmbH',
    author_email='rnd@de-cix.net',
    url='https://github.com/de-cix/pbgp-parser',
    keywords=['bgp', 'parsing', 'pcap'],
    license='Apache License 2.0',

    zip_safe=False,
    packages=packages,
    install_requires=requirements,
    entry_points={
        'console_scripts': [
            'pbgpp = pbgpp.Application.CLI:main'
        ]
    }
)
