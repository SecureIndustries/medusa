# medusa #

1. <a href="#1-overview">overview</a>
2. <a href="#2-download">download</a>
3. <a href="#3-build">build</a>
3. <a href="#4-benchmark">benchmark</a>

## 1. overview ##

medusa

## 2. download ##

    git clone --recursive https://github.com/SecureIndustries/medusa.git

or

    git clone https://github.com/SecureIndustries/medusa.git
    cd medusa
    git submodule update --init --recursive

## 3. build ##

    apt install gcc
    apt install make
    apt install pkg-config

    cd medusa
    make
    make tests

## 4. benchmark

C connections to URL, each connection sends N requests with interval I
milliseconds between requests using keep-alive K feature.

    medusa-server-benchmark -c C -n N -i I -k K -v 0 URL
