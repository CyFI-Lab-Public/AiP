# AiP

Following the paper of:
AI Psychiatry: Forensic Investigation of Deep Learning Networks in Memory Images
To appear in Usenix 2024.
https://www.usenix.org/conference/usenixsecurity24/presentation/oygenblik

AiP is built on top of the volatility3 framework. Clone this repo, and follow installation instructions at:
https://github.com/volatilityfoundation/volatility3
To get a clean install of volatility so that AiP is deployable. 

More details soon....
## Requirements
To run this simplified version of AiP the following must be installed/completed:
pyelftools == 0.29
torch == 1.11 (CPU or GPU)
python == 3.8 

To get Memory Images:
For CPU memory images utilize LiME: https://github.com/504ensicsLabs/LiME
For GPU memory images utilize Cuda-GDB.
Follow the instructions at: https://docs.nvidia.com/cuda/cuda-gdb/index.html#cuda-gdb-extensions
to get a complete core dump of the ML process you are attempting to investigate.


## Installing AiP
Simply clone this repository and follow the volatility3 Set up which can be found at: https://github.com/volatilityfoundation/volatility3
Install the packages in the requirements section.

## Using AiP
Navigate to the root directory of this repository.
Upon satisfying all prerequisites (setting up a conda environment with volatility3 installation requirements as well as the packages in ##Requirements
Run:
python vol.py -f ~/dumps/your_dump.lime linux.aip --pid PID --PyVersion 3_8_18
PID can be found with 
python vol.py -f ~/dumps/your_dump.lime linux.pslist

Update aip.py in the /plugins/linux/ folder to add more variants on Pyversions or add new framework versions. Add symbols to the framework/symbols/generic/types/ folders.
## Documentation
More documentation/information can be found in the paper: https://www.usenix.org/conference/usenixsecurity24/presentation/oygenblik
