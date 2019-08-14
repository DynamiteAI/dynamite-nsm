import os
import shutil
from setuptools import setup, find_packages
from setuptools.command.install import install


class PostInstallCommand(install):
    """Post-installation for installation mode."""
    def run(self):
        try:
            os.mkdir('/tmp/dynamite')
        except OSError:
            pass
        try:
            shutil.copytree('mirrors/', '/etc/dynamite/mirrors')
            shutil.copytree('default_configs/', '/etc/dynamite/default_configs')
        except Exception:
            print('[-] config directories already exist')
        install.run(self)


setup(
    name='dynamite-nsm',
    version='0.0.9',
    packages=find_packages(),
    scripts=['scripts/dynamite', 'scripts/dynamite.py'],
    url='http://vlabs.io',
    license='',
    author='Jamin Becker',
    author_email='jamin@vlabs.io',
    description='Dynamite-NSM is an network security monitor with an emphasis on very fast deployment, '
                'minimal configuration, and intuitive management.',
    include_package_data=True,
    cmdclass={
        'install': PostInstallCommand
    }
)
