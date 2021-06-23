# Overview

There are many variables that influence how you set up an agent, such as the hardware you have, 
the amount of traffic you expect, and the type of traffic you want to monitor. There are two paths 
for installing the agent.

<p align="center">
    <img src="/data/img/arch_agent.png"/>
</p>


1. **Install all the agent services on the same physical instance.** This is the easiest option but requires more serious 
[hardware](/requirements/02_agent_specifications).
   
2. **Install services on separate instances**. Useful when either Zeek or Suricata is not needed, or when the available hardware is below 
the above hardware specifications for a shared instance.
   


