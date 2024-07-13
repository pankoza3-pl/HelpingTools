from setuptools import setup, find_packages

setup(
    name='HelpingTools',
    version='1.0',
    packages=find_packages(),
    install_requires=[
        'cryptography',
    ],
    entry_points={
        'console_scripts': [
            'helpingtools = helpingtools:main',
        ],
    },
    author='Unknown',
    author_email='3652adamdir@gmail.com',
    description='An helper tool for various tasks.',
    long_description=open('README.md').read(),
    long_description_content_type='text/markdown',
    url='https://github.com/pankoza3-pl/HelpingTools/',
)