from distutils.core import setup

from setuptools import find_packages

# load VERSION from file
exec(open('agora/version.py').read())

with open('requirements.txt') as f:
    requires = f.readlines()
with open('requirements.dev.txt') as f:
    tests_requires = f.readlines()

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
