# LAVA Installation Guide

## Docker installation
    sudo apt-get install docker.io

## If that doesn’t work:
    sudo apt-get update
    sudo apt-get upgrade //optional

    sudo apt-key adv --keyserver hkp://ha.pool.sks-keyservers.net:80 \
                     --recv-keys 58118E89F3A912897C070ADBF76221572C52609D

    touch /etc/apt/source.list.d/docker.list

    echo "deb https://apt.dockerproject.org/repo ubuntu-xenial main" | sudo tee
    /etc/apt/sources.list.d/docker.list

    sudo apt-get update

    sudo apt-get install docker-engine
    sudo service docker start
NB: Change the distribution version name accordingly


## Git and Python installation
    sudo apt-get install git
    sudo apt-get install python
    sudo apt-get install python-pip
    sudo pip install --upgrade pip
    sudo pip install colorama

## Grant docker usage for non-root
    sudo usermod -a -G docker $USER
    su - $USER
    docker ps //test

## Clone the repository
    git clone git@bitbucket.org:moyix/lava.git

    or

    git clone https://$YOUR_USERNAME@bitbucket.org/moyix/lava.git

## Install LAVA
    cd lava
    python setup.py

## Try LAVA out
    python init-host.py
