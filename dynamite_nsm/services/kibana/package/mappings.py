
PACKAGES_INDEX_NAME = "dynamite-packages"
PACKAGES_INDEX_MAPPING = {
    "settings": {
        "number_of_shards": 1
    },
    "mappings": {
        "properties": {
            "destination_id": {
                "type": "text"
            },
            "id": {
                "type": "text"
            },
            "installed_objects": {
                "type": "nested",
                "properties": {
                    "object_id": {
                        "type": "text",
                        "fields": {
                                "keyword": {
                                    "type": "keyword",
                                    "ignore_above": 256
                                }
                        }
                    },
                    "object_type": {
                        "type": "text",
                        "fields": {
                                "keyword": {
                                    "type": "keyword",
                                    "ignore_above": 256
                                }
                        }
                    },
                    "title": {
                        "type": "text",
                        "fields": {
                                "keyword": {
                                    "type": "keyword",
                                    "ignore_above": 256
                                }
                        }
                    },
                    "tenant": {
                        "type": "text",
                        "fields": {
                                "keyword": {
                                    "type": "keyword",
                                    "ignore_above": 256
                                }
                        }
                    }
                }
            },
            "manifest": {
                "properties": {
                    "author": {
                        "type": "text",
                        "fields": {
                                "keyword": {
                                    "type": "keyword",
                                    "ignore_above": 256
                                }
                        }
                    },
                    "author_email": {
                        "type": "text",
                        "fields": {
                                "keyword": {
                                    "type": "keyword",
                                    "ignore_above": 256
                                }
                        }
                    },
                    "description": {
                        "type": "text",
                        "fields": {
                                "keyword": {
                                    "type": "keyword",
                                    "ignore_above": 256
                                }
                        }
                    },
                    "file_list": {
                        "type": "text",
                        "fields": {
                                "keyword": {
                                    "type": "keyword",
                                    "ignore_above": 256
                                }
                        }
                    },
                    "name": {
                        "type": "text",
                        "fields": {
                                "keyword": {
                                    "type": "keyword",
                                    "ignore_above": 256
                                }
                        }
                    },
                    "package_type": {
                        "type": "text",
                        "fields": {
                                "keyword": {
                                    "type": "keyword",
                                    "ignore_above": 256
                                }
                        }
                    },
                    "slug": {
                        "type": "text",
                        "fields": {
                                "keyword": {
                                    "type": "keyword",
                                    "ignore_above": 256
                                }
                        }
                    }
                }
            },
            "object_type": {
                "type": "keyword"
            },
            "overwrite": {
                "type": "boolean"
            },
            "package_name": {
                "type": "keyword"
            },
            "package_slug": {
                "type": "keyword"
            },
            "title": {
                "type": "text"
            }
        }
    }
}
