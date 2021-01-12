---
name: Bug report
about: Create a report to help us fix an issue you experienced.
labels: bug

---

**Title of the bug** 

*(e.g. Error with `--delete-temp-files`)*

**Description of the bug**

A clear and concise description of what the bug is. 
*(e.g. Used option `--delete-temp-files` did not delete all temporary files after failed transfer)*

**Used versions** (please complete the following information)
 - Operating System version: &nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;*(e.g. `Windows 10.0.19041`)*
 - Python version: &nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;*(e.g `3.7.0`)*
 - PyEGA3 version: &nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp; *(e.g `EGA python client version 3.4.0`)*
     - Please, **confirm you have tested your PyEGA3 installation** (follow [instructions](https://github.com/EGA-archive/ega-download-client#testing-pyega3-installation#Testing-pyEGA3-installation)):

Before creating a bug report, you may want to check if your issue is displayed in the [Troubleshooting](https://github.com/EGA-archive/ega-download-client#Troubleshooting). If the version of PyEGA3 you are using is not the most recent one, we strongly recommend updating PyEGA3 (follow instructions at [Installation and update](https://github.com/EGA-archive/ega-download-client#Installation-and-update)) and checking if the bug still appears.

**To Reproduce**

Steps to reproduce the behaviour that led you to the bug.
*e.g.:*
1. Trying to download BAM file `EGAF00001753754`.
```
pyega3 fetch -cf ./CREDENTIALS_FILE.json --format BAM --delete-temp-files --saveto ./Output/ EGAF00001775036
```
2. After 1 minute, interrupt transfer by exiting the terminal.
3. Check for temporary files.

**Observed behaviour**

A clear and concise description of what happened.
*(e.g. Temporary files remain after failed transfer)*

**Expected behaviour**

A clear and concise description of what you expected to happen.
*(e.g. Temporary files should be removed after failed transfer)*

**Screenshots and error messages**

If applicable, add screenshots or any error message (both printed to the terminal or to the `pyega3_output.log` log file) to help explain your problem.

**Additional context**

Add any other context about the problem here.
