#!/bin/bash
ip li set dev tun0 up
ip addr add 10.0.5.2 dev tun0
