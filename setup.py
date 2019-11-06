
from setuptools import setup, find_packages


setup(
    name='dynamite-nsm',
    version='0.5.4',
    packages=find_packages(),
    scripts=['scripts/dynamite', 'scripts/dynamite.py'],
    url='http://dynamite.ai',
    license='',
    author='Jamin Becker',
    author_email='jamin@dynamite.ai',
    description='Dynamite-NSM is an network security monitor with an emphasis on very fast deployment, '
                'minimal configuration, and intuitive management.',
    include_package_data=True,
    install_requires=[
        'pyyaml'
    ]
)
