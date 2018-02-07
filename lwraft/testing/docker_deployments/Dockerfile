FROM vmware/photon:latest
ENV container=docker
VOLUME ["/sys/fs/cgroup"]

RUN tdnf install -y lightwave-post
RUN curl -L https://vmware.bintray.com/photon_publish_rpms/x86_64/lmdb-0.9.21-1.ph2.x86_64.rpm -o lmdb.rpm
RUN rpm -ivh lmdb.rpm

COPY scripts/post_setup.sh /
COPY scripts/post_stat.sh /

RUN chmod +x /post_setup.sh
CMD ["/bin/bash"]
