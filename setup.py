from setuptools import setup, find_packages
setup(
    name='parsezeeklogs',
    version='2.0.1',
    description='A lightweight utility for programmatically reading and manipulating Zeek IDS (Bro IDS) log files and outputting into JSON or CSV format.',
    author='Dan Gunter',
    author_email='dangunter@gmail.com',
    url='https://github.com/dgunter/parsezeeklogs',
    packages=find_packages(include=['parsezeeklogs', 'parsezeeklogs.*']),
    install_requires=[
        'elasticsearch==7.16.1'
    ],
)

