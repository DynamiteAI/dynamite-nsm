function displayModalPluginInfo(){
    var tbody = "" +
           "<tr>" +
                "<td><b>Id</b></td>" +
                "<td style='color:blue'>" + pluginId + "</td>" +
          "</tr>" +
            "<tr>" +
                "<td><b>Name</b></td>" +
                "<td>" + pluginName + "</td>" +
          "</tr>" +
            "<tr>" +
                "<td><b>Description</b></td>" +
                "<td><p>" + pluginDescription + "</p></td>" +
          "</tr>" +
           "<tr>" +
                "<td><b>Version</b></td>" +
                "<td>" + pluginVersion + "</td>" +
          "</tr>";
     if (pluginAuthor != "None") {
        tbody += "" +
        "<tr>" +
                "<td><b>Author</b></td>" +
                "<td>" + pluginAuthor + "</td>" +
          "</tr>"
     }
   if (pluginWebsite != "None") {
        tbody += "" +
       "<tr>" +
            "<td><b>Website</b></td>" +
            "<td><a target='_blank' href='" + pluginWebsite + "'>"+pluginWebsite+"</a></td>" +
      "</tr>"
     }
    if (pluginRepo != "None") {
        tbody += "" +
       "<tr>" +
            "<td><b>Code Repo</b></td>" +
            "<td><a target='_blank' href='" + pluginRepo + "'>"+pluginRepo+"</a></td>" +
      "</tr>"
     }
    var dialog = "" +
    "<table>" +
        "<thead>" +
            "<tr><th></th></tr>" +
        "</thead>" +
        "<tbody>"+ tbody + "</tbody>" +

    "</table>";
    bootbox.dialog({
        message: dialog,
        size: 'large'
    });
}

function addDisplayModalPluginInfoListener(){
    $('#plugin-info').on("click", displayModalPluginInfo)
}

addDisplayModalPluginInfoListener();