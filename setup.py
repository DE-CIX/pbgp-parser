from setuptools import setup, find_packages

packages = ['pbgpp.' + pkg for pkg in find_packages('pbgpp')]
packages.append('pbgpp')

setup(
    name='pbgpp',
    version='0.2.17',
    description='PCAP BGP Parser',
    author='DE-CIX Management GmbH',
    author_email='rnd@de-cix.net',
    url='https://github.com/de-cix/pbgp-parser',
    keywords=['bgp', 'parsing', 'pcap'],
    license='Apache License 2.0',

    zip_safe=False,
    packages=packages,
    install_requires=['pcapy', 'kafka-python'],
    entry_points={
        'console_scripts': [
            'pbgpp = pbgpp.Application.CLI:main'
        ]
    }
)
