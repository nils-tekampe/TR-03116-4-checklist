#!/usr/local/bin/python
# -*- coding: utf-8 -*-

import os, logging, colorlog

# Helper function to check for the availability of streamripper.
# Thanks to http://stackoverflow.com/questions/377017/test-if-executable-exists-in-python
def which(program):
    def is_exe(fpath):
        return os.path.isfile(fpath) and os.access(fpath, os.X_OK)

    fpath, fname = os.path.split(program)
    if fpath:
        if is_exe(program):
            return program
    else:
        for path in os.environ["PATH"].split(os.pathsep):
            path = path.strip('"')
            exe_file = os.path.join(path, program)
            if is_exe(exe_file):
                return exe_file

logger = colorlog.getLogger("checklist.py")
logger.setLevel(logging.INFO)
sh = colorlog.StreamHandler()
formatter = sh.setFormatter(colorlog.ColoredFormatter('%(log_color)s%(name)s:%(message)s'))
logger.addHandler(sh)
