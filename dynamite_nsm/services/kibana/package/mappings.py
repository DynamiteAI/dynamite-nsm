
PACKAGES_INDEX_NAME = "dynamite-packages"
PACKAGES_INDEX_MAPPING = {
    "settings": {
        "number_of_shards": 1
    },
    "mappings": {
            "properties": {
                "id": { "type": "text" },
                "package_slug": { "type": "keyword" },
                "package_name": { "type": "keyword" },
                "object_type": { "type": "keyword" },
                "title": { "type": "text" },
                "overwrite": { "type": "boolean" },
                "destination_id": { "type": "text" }
            }
        }
    }
