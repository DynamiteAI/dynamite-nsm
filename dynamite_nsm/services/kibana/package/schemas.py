from marshmallow import Schema, fields, validate, ValidationError
import json

INSTALLED_KIBANA_PACKAGES_FILE_BASE = {'installed_packages': {}}

ORPHAN_OBJECT_PACKAGE_MANIFEST_DATA = {
    'name': 'Orphaned Objects',
    'author': 'dynamite.ai',
    'package_type': 'system',
    'description': 'This package contains all orphaned packages installed directly from a file.',
    'file_list': ['default.ndjson']
}


class SchemaToObject:
    def __init__(self, json_data, object_schema):

        if type(json_data) == dict:
            self.data = object_schema.load(json_data)
        elif type(json_data) == str:
            self.data = object_schema.loads(json_data)
        else:
            raise ValidationError("Invalid input type. must be one of: str, dict")

        for key, value in self.data.items():
            setattr(self, key, value)

    def json(self) -> str:
        return json.dumps(self.data)


class InstalledPackagesListSchema(Schema):
    installed_packages = fields.Dict(required=True)


class InstalledObjectSchema(Schema):
    object_id = fields.String(required=True)
    object_type = fields.String(required=True)
    title = fields.String(required=True)
    overwrite = fields.Boolean(required=False, default=False, allow_none=True)
    destination_id = fields.String(required=False, default=None, allow_none=True)
    tenant = fields.String(required=False, default=None, allow_none=True)


class PackageManifestSchema(Schema):
    name = fields.String(required=True, validate=validate.Length(1))
    author = fields.String(required=False)
    package_type = fields.String(required=True, validate=validate.OneOf(['saved_objects', 'system']))
    description = fields.String(required=True, validate=validate.Length(1, 512))
    file_list = fields.List(fields.String,
                            required=True,
                            # TODO: Regex validation for supported filetypes
                            validate=validate.Length(1))
    author_email = fields.String(required=False, default="")
    slug = fields.String(required=False, default=None)
