#!/bin/sh
# A failed safety hook must never return control to the partitioner.
echo 'ZAPDOS STOPPED: safety/configuration check failed. No further writes will be made.' >/dev/console
while :; do sleep 3600; done
