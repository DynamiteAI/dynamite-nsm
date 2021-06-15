from dynamite_nsm.services.base import tasks


class InstallKibanaDynamiteInvestigatorPackage(tasks.BaseKibanaPackageInstallTask):
    def __init__(self, username: str, password: str, target: str):
        super().__init__(name='install_dynamite_investigator',
                         kibana_package_link='https://github.com/DynamiteAI/kibana_packages/blob/main/'
                                             'dynamite_investigator/dist/dynamite-investigator.tar.xz?raw=true',
                         username=username,
                         password=password,
                         target=target,
                         tenant='',
                         description='Install the Dynamite Investigator Kibana package.')


if __name__ == '__main__':
    from dynamite_nsm import utilities

    task = InstallKibanaDynamiteInvestigatorPackage(username='admin', password='admin',
                                                    target=f'https://{utilities.get_primary_ip_address()}:9200')
    task.download_and_install()
