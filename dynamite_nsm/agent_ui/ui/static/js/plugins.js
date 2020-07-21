function initializePluginUploadComponent(){
    $(document).ready(function()
        {
            $("#plugin-uploader").uploadFile({
                url:"/plugins/install_plugin_ajax",
                fileName:"file",
                dragdropWidth: "100%",
                statusBarWidth: "100%",
                allowedTypes: "zip",
                onSuccess: function(files, data, xhr, pd){
                    if (data['message'] !== undefined) {
                        window.location = '/plugins'
                    } else {
                        $('#error_type').val(data["error_type"]);
                        $('#error_message').val(data["error_message"]);
                        $('#error_traceback').val(data["error_traceback"]);
                        $('#error_form').submit();
                    }

                },
            });
        });
}

initializePluginUploadComponent();