#!/bin/bash
ip li set dev tun0 up
ip addr add 10.0.5.3/24 dev tun0
