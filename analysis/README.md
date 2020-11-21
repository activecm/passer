# Analyzing Passer Results
### Running the program
If you're working wiwth the source code just cd to the directory of the analyser file and run  
```Python3 analyzer.py -i <name-of-logfile-to-import>```  
The file extension does not matter, but the file must be comma separated
### Filters
The filter options are listed below. After running the program type ```filter``` followed by any combination of the following  
- type={TC, TS, UC, US, RO, DN, MA}  
- ip={127.0.0.1, or whatever} 
  - set 'ippref=true' to do searches such as 10.0.*
- ipv={4, 6, 0 for all} 
- state={open, suspicious, etc...}

example: If you wanted to show all ipv4 addresses that were flagged as suspicious, you would type the following  
```filter ipv=4 state=suspicious```  
or to see all TCP clients starting wih address 10.0.0.*  
```filter type=TC ip=10.0.0 ippref=true```  
to reset the filters type ```reset``` at the command prompt

### Commands
- reset --resets the filters  
- show --shows the results (shrinks to fit on screen)  
- show-all --shows all results (use with caution)  
- quit --gracefully exits the program  

### Bugz
feel free to report bugs or suggestions to hcartier@activecountermeasures.com