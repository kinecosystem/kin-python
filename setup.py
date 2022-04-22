from distutils.core import setup

from setuptools import find_packages

# load VERSION from file
exec(open('agora/version.py').read())

# Keep this aligned with requires.txt
requires = [
    'grpcio==1.34.1',
    'agora-api==0.26.0',
    'kin-base==1.4.1',
    'ed25519==1.4; sys_platform != "win32" and sys_platform != "cygwin"',
    'pure25519==0.0.1',
    'protobuf==3.12.2',
    'pynacl==1.4.0',
    'base58==2.0.1'
]

# Keep this aligned with requires.dev.txt
tests_requires = {
    'Flask==1.1.2',
    'grpcio-testing==1.30.0',
    'pytest==5.4.3',
    'pytest-cov==2.10.0',
    'pytest-freezegun==0.4.2',
    'pytest-mock==3.2.0',
    'pytest-timeout==1.4.1',
    'sphinx==3.1.2',
    'sphinx-autodoc-typehints==1.11.0'
}

setup(
    name='kin-sdk-v2',
    version=VERSION,
    description='Kin SDK for Python',
    author='Kik Engineering',
    author_email='engineering@kik.com',
    url='https://github.com/kinecosystem/kin-python',
    license='MIT',
    packages=find_packages(include=["agora", "agora.*"]),
    long_description=open("README.md").read(),
    long_description_content_type="text/markdown",
    keywords=["kin", "agora", "stellar", "blockchain", "cryptocurrency"],
    classifiers=[
        'License :: OSI Approved :: MIT License',
        'Intended Audience :: Developers',
        'Topic :: Software Development :: Libraries :: Python Modules',
        'Programming Language :: Python',
        'Programming Language :: Python :: 3',
    ],
    install_requires=requires,
    tests_requires=tests_requires,
    python_requires='>=3.6'
)
