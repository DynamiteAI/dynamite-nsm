from flask_restplus import fields

# multiple endpoints
response_error = dict(
    message=fields.String
)

# multiple endpoints

response_success = dict(
    message=fields.String
)

# GET /config
response_list_components_model = dict(
    components=dict(
        manager=fields.Nested(
            dict(
                host=fields.String,
                type=fields.String
            )
        ),
        loggers=fields.List(fields.Nested(
            dict(
                host=fields.String,
                type=fields.String
            )
        )),
        proxies=fields.List(fields.Nested(
            dict(
                host=fields.String,
                type=fields.String
            )
        )),
        workers=fields.List(fields.Nested(
            dict(
                type=fields.String,
                interface=fields.String,
                lb_method=fields.String,
                lb_procs=fields.String,
                pin_cpus=fields.String,
                host=fields.String
            )
        )),
    )
)

# GET /config/<component>
response_get_component_model = dict(
    component=fields.List(fields.Nested(dict(
        host=fields.String,
        type=fields.String
    )))
)

# GET  config/worker/<name>
# POST config/worker/<name>
# PUT  config/worker/<name>
response_get_worker = dict(
    type=fields.String,
    interface=fields.String,
    lb_method=fields.String,
    lb_procs=fields.String,
    pin_cpus=fields.String,
    host=fields.String
)
