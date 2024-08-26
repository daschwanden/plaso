FROM ubuntu:24.04

RUN apt-get update -q && \
    apt-get install -y libterm-readline-gnu-perl locales software-properties-common vim && \
    locale-gen en_US.UTF-8 && \
    ln -f -s /usr/share/zoneinfo/UTC /etc/localtime && \
    apt-get install -y git python3 sudo

COPY . plaso/

RUN plaso/config/linux/ubuntu_install_plaso.sh

# PYTHONPATH=. python3 plaso/scripts/log2timeline.py --status_view linear --storage_file test.plaso test_data/image.qcow2
# PYTHONPATH=. python3 plaso/scripts/psort.py --status_view linear -w timeline.log test.plaso
