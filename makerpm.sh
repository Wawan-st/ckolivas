#!/bin/sh

MODULES=icarus,bitmine_A1

#rpmbuild -bc  --short-circuit --define "modules $MODULES"  spec/cgminer.spec
rpmbuild -bb  --define "modules $MODULES"  spec/cgminer.spec
