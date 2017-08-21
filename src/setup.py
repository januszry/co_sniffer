#!/usr/bin/env python3

import sys
from setuptools import setup, find_packages

if sys.version_info.major == 3:
    scapy_dist = 'scapy-python3>=0.1.6'
else:
    scapy_dist = 'scapy>=2.3.1'


setup(
    name='co_sniffer',
    version='0.2.4',
    keywords=('sniff', 'packet', 'streaming', 'wmsp', 'mms', 'rtmp'),
    description='Media stream sniffer based on scapy-python3',
    license='MIT License',

    url='',
    author='zengruoyu',
    author_email='zengruoyu@qingtingfm.com',

    packages=find_packages(),
    include_package_data=True,
    platforms='any',
    install_requires=[
        scapy_dist,
        'netifaces>=0.10.4',
        'scapy-python3>=0.21',
        ],
    entry_points={
        'console_scripts': [
            'co_sniffer=co_sniffer.sniffer:main',
        ]},
)
