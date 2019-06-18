from installer import elasticsearch

config = elasticsearch.ElasticConfigurator('/etc/dynamite/elasticsearch/')
config.write_configs()
