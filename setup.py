
from setuptools import setup, find_packages

with open("PROJECT_DESCRIPTION.md", "r") as fh:
    long_description = fh.read()

setup(
    name='dynamite-nsm',
    version='0.8.0',
    packages=find_packages(),
    scripts=['scripts/dynamite'],
    url='http://dynamite.ai',
    long_description=long_description,
    long_description_content_type="text/markdown",
    license='GPL 3',
    author='Jamin Becker',
    author_email='jamin@dynamite.ai',
    description='DynamiteNSM is an network security monitor with an emphasis on very fast deployment, '
                'minimal configuration, and intuitive management.',
    include_package_data=True,
    install_requires=[
        'coloredlogs',
        'progressbar',
        'tabulate',
        'pyyaml',
        'npyscreen',
        'psutil',
        'docstring-parser==0.7.3'
    ],
    classifiers=[
        'Development Status :: 3 - Alpha',
        'Natural Language :: English',
        'Programming Language :: Python',
        'Operating System :: POSIX :: Linux',
        'Environment :: Console',
        'Topic :: System :: Networking :: Monitoring',
        'Topic :: Security'
    ]
)
