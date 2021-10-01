FROM centos:8.4.2105

# Install dependencies
RUN dnf module -y install python38
RUN dnf install -y python38-devel epel-release dnf-plugins-core git kernel-headers
RUN yum config-manager --set-enabled powertools

# Setup NSM module and commandline
ADD . dynamite-nsm/
RUN python3.8 -m pip install dynamite-nsm/ GitPython semantic-version
RUN sed -i 's/#!python/#!\/usr\/bin\/python3.8/g' /usr/local/bin/dynamite

# Install Zeek
RUN dynamite zeek install --inspect-interfaces=eth0 --verbose
WORKDIR /tmp/zeek-af_packet-plugin
RUN git clone https://github.com/J-Gras/zeek-af_packet-plugin.git /tmp/zeek-af_packet-plugin  \
    && cd /tmp/zeek-af_packet-plugin \
    && ./configure --with-kernel=/usr --zeek-dist=/tmp/dynamite/install_cache/zeek-4.0.3  \
    && make -j 2 \
    && make install

# Install Suricata
RUN dynamite suricata install --inspect-interfaces=eth0 --verbose

# Install Filebeat
RUN dynamite filebeat install --targets=localhost:9200 --verbose

# Start
CMD dynamite agent process start && dynamite filebeat logs main --pretty
