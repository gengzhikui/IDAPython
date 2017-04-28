# -*- coding: utf-8 -*-
"""
used for calculate the number of instructions of a binary file
the result will be written in ./data.txt
"""

from idaapi import *
import idc

def getInstrsByAddr(tgtEA):
    func = get_func(tgtEA)
    numInstructions = 0;
    if not func is None:
        fname = Name(func.startEA)
        count = 0
        for i in FuncItems(func.startEA): 
            count = count + 1
            numInstructions = numInstructions + 1
            # Message("%s contains %d instructions\n" % (fname,count))
    else:
        Warning("No function found at location %x" % here())
    
    return numInstructions

def main():
    funcs = Functions()
    totalInstrs = 0;
    for f in funcs:
        name = Name(f)
        end = GetFunctionAttr(f, FUNCATTR_END)
        locals = GetFunctionAttr(f, FUNCATTR_FRSIZE)
        
        funcInstrs = getInstrsByAddr(f)
        totalInstrs += funcInstrs
        
        # Message("Function: %s, starts at %x, ends at %x, with %d instructions\n" % (name, f, end, funcInstrs))
    Message("Total: %d Instructions\n" % (totalInstrs));
    
    log_file_uri = os.path.dirname(os.path.realpath(__file__)) + '/data.txt'
    log_file = open(log_file_uri, 'a')        
    log_file.write('Total Instructions: ' + str(totalInstrs) + '\n')
    log_file.close()

    # return 1
    idc.Exit(0); #Exit IDA Pro


if __name__ == '__main__':
    main()