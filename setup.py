
from setuptools import setup, find_packages

with open("PROJECT_DESCRIPTION.md", "r") as fh:
    long_description = fh.read()

setup(
    name='dynamite-nsm',
    version='0.7.1',
    packages=find_packages(),
    scripts=['scripts/dynamite'],
    url='http://dynamite.ai',
    long_description=long_description,
    long_description_content_type="text/markdown",
    license='GPL 3',
    author='Jamin Becker',
    author_email='jamin@dynamite.ai',
    description='Dynamite-NSM is an network security monitor with an emphasis on very fast deployment, '
                'minimal configuration, and intuitive management.',
    include_package_data=True,
    install_requires=[
        'coloredlogs',
        'flask',
        'Flask',
        'email_validator',
        'flask-restplus',
        'flask-security',
        'flask-sqlalchemy',
        'progressbar',
        'pyyaml',
        'npyscreen',
        'psutil'
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
