from setuptools import setup, find_packages

setup(
    name='dynamite-nsm',
    version='1.1.0',
    packages=find_packages(),
    scripts=['scripts/dynamite'],
    url='https://github.com/DynamiteAI/dynamite-nsm',
    long_description_content_type="text/markdown",
    license='GPL 3',
    author='Dynamite Analytics',
    author_email='admin@dynamite.ai',
    description='DynamiteNSM is a lightweight, versatile network security monitor designed to '
                'make securing your network environment simple and intuitive.',
    include_package_data=True,
    install_requires=[
        'bcrypt==3.1.7',
        'coloredlogs==15.0',
        'progressbar==2.5',
        'tabulate==0.8.9',
        'PyYAML==5.3.1',
        'psutil==5.8.0',
        'docstring-parser=>0.5',
        'marshmallow==3.11.1',
        'pytest==6.2.2',
        'python-crontab==2.5.1',
        'python-daemon==2.3.0',
        'requests==2.25.1',
        'sqlalchemy==1.3.18',
        'Unidecode==1.2.0',
    ],
    classifiers=[
        'Development Status :: 4 - Beta',
        'Natural Language :: English',
        'Programming Language :: Python :: 3.7',
        'Operating System :: POSIX :: Linux',
        'Environment :: Console',
        'Topic :: System :: Networking :: Monitoring',
        'Topic :: Security',
        'License :: OSI Approved :: GNU General Public License (GPL)'
    ]
)
