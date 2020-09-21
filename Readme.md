# Description
*  memgrep volatility plugin
* Given a string or regular expression, the plugin should print all its occurrences and for each one tells where it is located in the memory dump (physical and virtual address, allocated or unallocated block, kernel vs process memory, heap vs stack vs data sections, … )
* This is somehow similar to yarascan or running strings+memap plugin, but should give much more information.

# COMMANDS
* volatility --plugins="directoryPlugin" -f <dump> --profile=<windows profile> project_v1 -r <regex> <optional options> <optional rendering>

* optional options :
  * -I: for IGNORE_CASE
  * -p <pid>

* optional rendering (example html)
  * --output=html --output-file=project.html

# important notes :
* only use on linux dumps
