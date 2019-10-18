from setuptools import setup, find_packages

version = '1.0'

with open('README.rst') as f:
    long_description = ''.join(f.readlines())

test_require = [
    'codacy-coverage',
    'coveralls',
    'flake8',
    'pytest',
    'pytest-cov',
    'pytest-env',
    'pytest-flask==0.11.0'
]

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
        'Flask==1.0',
        'Flask-Babel==0.11.2',
        'Flask-Cache',
        'Flask-WTF',
        'gunicorn',
        'python-dateutil',
        'pyyaml',
        'python-slugify',
        'pytz',
        'urllib3==1.22'
    ],
    setup_requires=[
        'pytest-runner',
    ],
    tests_require=test_require,
    extras_require={
        'test': test_require,
        'dev': test_require + [
            'ipython',
            'sphinx',
            'sphinx-autobuild',
            'sphinx_rtd_theme',
        ]
    },
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
