from setuptools import setup

setup(
    name='dls'
         'ynamite-nsm',
    version='0.0.9',
    packages=['lib', 'lib.services'],
    include_package_data=True,
    scripts=['scripts/dynamite', 'scripts/python/dynamite.py'],
    url='http://vlabs.io',
    license='',
    author='Jamin Becker',
    author_email='jamin@vlabs.io',
    description='Dynamite-NSM is an network security monitor with an emphasis on very fast deployment, '
                'minimal configuration, and intuitive management.'
)
