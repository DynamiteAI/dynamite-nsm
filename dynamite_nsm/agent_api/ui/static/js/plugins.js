function initializePluginUploadComponent(){
    $(document).ready(function()
        {
            $("#plugin-uploader").uploadFile({
                url:"/plugins/install_plugin_submit",
                fileName:"file",
                dragdropWidth: "100%",
                statusBarWidth: "100%",
                allowedTypes: "zip",
                onSuccess: function(files, data, xhr, pd){
                    window.location = '/plugins'
                }
            });
        });
}

initializePluginUploadComponent();