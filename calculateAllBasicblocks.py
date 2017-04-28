# -*- coding: utf-8 -*-
"""
used for calculate the number of basicblocks of a binary file
the result will be written in ./data.txt
"""

import idaapi
import idc

def getBasicblocksByAddr(tgtEA):
    if tgtEA is None:
      exit

    f = idaapi.get_func(tgtEA)
    if not f:
        print "No function at 0x%x" % (tgtEA)
        exit

    fc = idaapi.FlowChart(f)
    
    numBlocks =0;
    for block in fc:
        # print "block [0x%x - 0x%x)" % (block.startEA, block.endEA)
        numBlocks = numBlocks + 1;
      #if block.startEA <= tgtEA:
      #if block.endEA > tgtEA:
          #print "0x%x is part of block [0x%x - 0x%x)" % (tgtEA, block.startEA, block.endEA)  
    
    return numBlocks

def main():
    funcs = Functions()
    totalBlocks = 0;
    for f in funcs:
        name = Name(f)
        end = GetFunctionAttr(f, FUNCATTR_END)
        locals = GetFunctionAttr(f, FUNCATTR_FRSIZE)
        
        functionBasicBlocks = getBasicblocksByAddr(f)
        totalBlocks += functionBasicBlocks
        
        # Message("Function: %s, starts at %x, ends at %x, with %d blocks\n" % (name, f, end, functionBasicBlocks))
    Message("Total: %d blocks\n" % (totalBlocks));
    
    log_file_uri = os.path.dirname(os.path.realpath(__file__)) + '/data.txt'
    log_file = open(log_file_uri, 'a')        
    log_file.write('Total basicblocks: ' + str(totalBlocks) + '\n')
    log_file.close()

    # return 1
    idc.Exit(0); # Exit IDA Pro

if __name__ == '__main__':
    main()