import sys
from setuptools import setup, find_packages


setup(
    name='co_sniffer',
    version='0.2.5',
    keywords=['sniff', 'packet', 'streaming', 'wmsp', 'mms', 'rtmp'],
    description='Media stream sniffer based on scapy-python3',
    license='MIT License',

    url='',
    author='coppla',
    author_email='januszry@gmail.com',

    packages=find_packages(),
    include_package_data=True,
    platforms='any',
    install_requires=[
        'scapy>=2.4.0',
        'netifaces>=0.10.4',
        ],
    entry_points={
        'console_scripts': [
            'co_sniffer=co_sniffer.sniffer:main',
        ]},
)
