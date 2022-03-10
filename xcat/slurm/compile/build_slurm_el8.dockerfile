FROM almalinux:8

ARG SLURMVERSION
ARG SLURMRELEASE

USER 0

RUN dnf -y install epel-release dnf-plugins-core && \
    yum config-manager --set-enabled powertools && \
    dnf -y install gcc gcc-c++ perl python3 rpm-build git cmake wget && \
    dnf -y install munge-devel make hwloc-devel rrdtool-devel mysql-devel pam-devel ncurses-devel freeipmi-devel \
                    openssl-devel readline-devel numactl-devel lua-devel gtk2-devel perl-ExtUtils-MakeMaker man2html \
                    hdf5-devel libibmad-devel rdma-core-devel libcurl-devel libssh2-devel lz4-devel \
                    json-c-devel http-parser-devel libjwt-devel

RUN mkdir /build && \
    mkdir /build/slurm

RUN echo "#!/bin/bash" > /build/slurm/build_slurm.sh && \
    echo "wget https://download.schedmd.com/slurm/slurm-${SLURMVERSION}${SLURMRELEASE}.tar.bz2" | tee -a /build/slurm/build_slurm.sh && \
    echo "rpmbuild -ts slurm-${SLURMVERSION}${SLURMRELEASE}.tar.bz2" | tee -a /build/slurm/build_slurm.sh && \
    echo "cd /root/rpmbuild/" | tee -a /build/slurm/build_slurm.sh && \
    echo "rpm --install ./SRPMS/slurm-${SLURMVERSION}*.src.rpm" | tee -a /build/slurm/build_slurm.sh && \
    echo "sed -i -e '/Release:/a Epoch:          %{expand:%(date +%%Y%%m%%d)}' -e 's|%{version}-%{release}|%{epoch}:%{version}-%{release}|g' ./SPECS/slurm.spec" | tee -a /build/slurm/build_slurm.sh && \
    echo "rpmbuild -ba ./SPECS/slurm.spec --define \"_with_lua 1\" --define \"_with_mysql 1\" --define \"_with-http-parser /usr/local/\" --define \"_with_slurmrestd 1\" --define \"_with-jwt /usr/lib64\"" | tee -a /build/slurm/build_slurm.sh && \
    echo "cp /root/rpmbuild/RPMS/x86_64/* /tmp/slurm/" | tee -a /build/slurm/build_slurm.sh && \
    chmod +x /build/slurm/build_slurm.sh

WORKDIR /build/slurm/

ENTRYPOINT [ "/build/slurm/build_slurm.sh" ]