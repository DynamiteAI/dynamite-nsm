# Project Goals

Passive network monitoring is an approach to network monitoring where traffic is "sniffed" via
strategically placed sensors on critical junctions of your network. DynamiteNSM aims to make the process of setting up
the sensor and monitoring infrastructure needed to collect and make sense of this data as seamless as possible.

DynamiteNSM was built around several design goals to make it an attractive alternative to heavier weight NSMs.

1. **Minimal-knowledge Deployment**: A user should be able to get to a working state with minimal or 
   no documentation.
2. **Intelligent Defaults**: A user is not required to understand the intricacies of our stack to start running with 
   reasonable configurations.
3. **Unified Utility for Management**: All the tools for installing, managing, and monitoring Dynamite services should 
   be accessible in a single utility. 
4. **SDKs for Everything**: Every installable service in the DynamiteNSM can be controlled through a set of Python 
   libraries. Users should always have the option of building their own interfaces to manage these services.
5. **Extremely Customizable**: A user should be able to customize DynamiteNSM to fit a variety of operational, 
   threat-hunting, and detection use-cases.
   
