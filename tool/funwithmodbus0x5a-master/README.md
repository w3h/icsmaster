# funwithmodbus0x5a

Material from my ICS Village talk at DEFCON 25

*This is a temporary repo to store and make available the tools used during the talks*

*The scripts should be finalized and integrated into Metasploit*

# Talks
The slides are located on [Google Slides](https://docs.google.com/presentation/d/1K79add5Nqdlh8rBa2XrvcmSOGvPCnQE-leJSrkkKH5E/edit?usp=sharing)
Some demo videos can be found [here](https://drive.google.com/drive/folders/0BwnYYhA62txMOTZibnlOckdFcHM?usp=sharing)

# Description
+ `modicon_stux_transfer_ASO.rb`: allows downloading a program from the PLC
+ `schneider.rb`: allows to gather information about the PLC (*GATHER_INFOS*) and to force the values of the digital outputs (*M340_FORCE_OUTPUTS*)
+ `modicon_command_CTv2.rb`: work by Alexandrine TORRENTS to allow START/STOP on TM221 PLCs.
