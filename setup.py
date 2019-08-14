import os
import time
import shutil
from setuptools import setup, find_packages
from setuptools.command.install import install
from setuptools.command.develop import develop
from setuptools.command.egg_info import egg_info


def post_install_cmds():
    try:
        os.mkdir('/tmp/dynamite')
    except OSError:
        pass
    shutil.rmtree('/tmp/dynamite/', ignore_errors=True)
    shutil.rmtree('/etc/dynamite/mirrors/', ignore_errors=True)
    shutil.rmtree('/etc/dynamite/default_configs/', ignore_errors=True)
    time.sleep(1)
    try:
        print('Copying default_configs -> /etc/dynamite/default_configs')
        shutil.copytree('default_configs/', '/etc/dynamite/default_configs')
        print('Copying mirrors -> /etc/dynamite/mirrors')
        shutil.copytree('mirrors/', '/etc/dynamite/mirrors')
    except Exception:
        print('[-] config directories already exist')


class PostInstallCommand(install):
    """Post-installation for installation mode."""
    def run(self):
        install.run(self)
        post_install_cmds()


class PostDevelopCommand(develop):
    def run(self):
        develop.run(self)
        post_install_cmds()


class PostEggInfoCommand(egg_info):
    def run(self):
        egg_info.run(self)
        post_install_cmds()


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
        'install': PostInstallCommand,
        'develop': PostDevelopCommand,
        'egg_info': PostEggInfoCommand
    }
)
