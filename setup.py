from setuptools import setup, find_packages

version = '0.3'

with open('README.rst') as f:
    long_description = ''.join(f.readlines())

setup(
    name='kqueen-ui',
    version=version,
    description='UI for Kubernetes cluster orchestrator',
    long_description=long_description,
    author='Adam Tengler',
    author_email='atengler@mirantis.com',
    license='MIT',
    url='https://github.com/atengler/kqueen-ui/',
    download_url='https://github.com/atengler/archive/v{}.tar.gz'.format(version),
    packages=find_packages(),
    zip_safe=False,
    install_requires=[
        'Flask==0.12.2',
        'Flask-Babel==0.11.2',
        'Flask-Cache',
        'Flask-WTF',
        'gunicorn',
        'python-dateutil',
        'pyyaml',
        'urllib3'
    ],
    classifiers=[
        'Operating System :: POSIX :: Linux',
        'Programming Language :: Python',
        'Programming Language :: Python :: Implementation :: CPython',
        'Programming Language :: Python :: 3',
        'Programming Language :: Python :: 3.6',
    ],
    entry_points={
        'console_scripts': [
            'kqueen-ui = kqueen_ui.server:run',
        ],
    },
)
