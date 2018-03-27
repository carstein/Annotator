#!/usr/bin/env python
# Author: carstein <michal.melewski@gmail.com>
# Annotate function arguments

from binaryninja import PluginCommand
from modules import annotate


# register plugin
PluginCommand.register_for_function(
  "[Annotator] Annotate Functions",
  "Annotate standard libc functions with arguments",
  annotate.run_plugin)
