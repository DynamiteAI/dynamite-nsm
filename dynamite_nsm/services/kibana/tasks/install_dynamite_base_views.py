from dynamite_nsm.services.base import tasks


class InstallKibanaDynamiteBaseViewsPackage(tasks.BaseKibanaPackageInstallTask):
    def __init__(self, username: str, password: str, target: str):
        super().__init__(name='install_base_views',
                         kibana_package_link='https://github.com/DynamiteAI/kibana_packages/blob/main/BaseViews/dist/'
                                             'BaseViews.tar.gz?raw=true',
                         username=username,
                         password=password,
                         target=target,
                         tenant='',
                         description='Install the BaseViews Kibana package.')


if __name__ == '__main__':
    from dynamite_nsm import utilities

    task = InstallKibanaDynamiteBaseViewsPackage(username='admin', password='admin',
                                                 target=f'https://{utilities.get_primary_ip_address()}:9200')
    task.download_and_install()
