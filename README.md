# medusa #

1. <a href="#1-overview">overview</a>
2. <a href="#2-download">download</a>
3. <a href="#3-build">build</a>

## 1. overview ##

medusa

## 2. download ##

    git clone --recursive git@github.com:alperakcan/mbus.git

or

    git clone git@github.com:alperakcan/mbus.git
    cd mbus
    git submodule update --init --recursive

## 3. build ##

    apt install gcc
    apt install make
    apt install pkg-config
    apt install libssl-dev
    apt install libreadline-dev

    cd medusa
    make
