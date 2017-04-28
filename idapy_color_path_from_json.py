# -*- coding: utf-8 -*-
"""
input: the json produced by dynamoRIO
output: the running trace in IDA controlflow
"""

import json
import idc
import idaapi
from collections import defaultdict

def color(ea, nbins, c):
    '''Color 'nbins' instructions starting from ea'''
    colors = defaultdict(int, {
            'black' : 0x000000,
            'red' : 0x0000FF,
            'blue' : 0xFF0000,
            'green' : 0x00FF00
        }
    )
    for _ in range(nbins):
        idaapi.del_item_color(ea)
        idaapi.set_item_color(ea, colors[c])
        ea += idc.ItemSize(ea)

def main():
    f = open(idc.AskFile(0, '*.json', 'Where is the JSON report you want to load ?'), 'r')
    c = idc.AskStr('black', 'Which color do you want ?').lower()
    report = json.load(f)
    for i in report['basic_blocks_info']['list']:
        if i['module_id'] == 0:
            # print '%x' % i['start_addr'],
            try:
                # start_addr + 0x01000000
                color(i['start_addr'] + 16777216 , i['num_instrs'], c)
                # print 'ok'
            except Exception, e:
                print 'fail: %s' % str(e)
    print 'done'    
    return 1

if __name__ == '__main__':
    main()