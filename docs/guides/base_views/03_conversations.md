# Conversations

The `Conversations` module contains views built for the analysis of host-to-host communications that are not necessarily associated with a suspicious traffic alert.  The primary view contains a histogram depicting the volume of connections over time as well as high-level metrics describing the nature of the traffic that occurred during the time frame. Additionally you'll find lists of top-talkers, top ports, and application protocols that can serve as a starting point for more focused threat hunts.

## Conversations Map

The `Conversations Map` view includes a world map with individual countries colorized to depict the volume of connections that originated from within.  Click on a specific country to filter the conversations for traffic that it was involved in.  

<p align="center">
    <img src="/data/img/kibana_conversation_map.png" />
</p>

## Discovery View

The conversations `Discovery View` is a customized data table built for exploring conversation records.  Use the search bar and filters to refine the conversations included in the data table.  Expand the details to learn more about the nature of the conversation and to access pivots to other related views. 

<p align="center">
    <img src="/data/img/kibana_conversations_discovery_view.png" />
</p>
