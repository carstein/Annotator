#!/usr/bin/env python
# author: carstein <michal.melewski@gmail.com>
# Annotate function with prototype

import os
import json
from binaryninja import PluginCommand

from modules import annotate


# register plugin
PluginCommand.register_for_function(
  "Annotate Functions",
  "Annotate standard libc functions with arguments",
  annotate.run_plugin)
