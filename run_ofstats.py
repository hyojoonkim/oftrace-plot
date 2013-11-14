################################################################################
# SDN 8001 
# Author: Hyojoon Kim (joonk@gatech.edu)                                       
# Desc: 
#   Run ofdump, get dumps, save info as pickled data.
# Output:
################################################################################

from optparse import OptionParser
import sys
import re
import string
import pickle
import time
import os
from subprocess import Popen, PIPE

import openflow as of

def main():

  desc = ( 'Run ofdump on pcap, get dumps, save info.' )
  usage = ( '%prog [options]\n'
            '(type %prog -h for details)' )
  op = OptionParser( description=desc, usage=usage )

  # Options
  op.add_option( '--ofdumpcmd', '-d', action="store", \
                 dest="ofdump_cmd", help = "Path to ofdump command.")

  op.add_option( '--pcap', '-p', action="store", \
                 dest="pcap_file", help = "Path to PCAP file.")


  # Parsing and processing
  options, args= op.parse_args()

  # Do the job. 
  output = run_oftrace(options.ofdump_cmd, options.pcap_file)
  dump_map = {}
  dump_map = analyze_output(output)
  return 


def run_oftrace(ofcmd, pcap):
  
  cmd_str = ofcmd + ' ' + pcap
  proc = Popen(cmd_str, shell=True, stdout=PIPE)
  output = proc.communicate()[0]

  return output


def analyze_output(output):

  all_map = {}
  from_controller_map = {}
  from_swt_map = {}

  ## coming from switch
  packet_in_map = {}

  ## coming from contoller
  packet_out_map = {}
  flow_mod_map = {}

  out_list= output.split('\n')  

  for u in out_list:
    if u.startswith('FROM') is True:
      line_list = u.split('\t')

      #  Time
      time_str = line_list[5]
      time_number = round(float(time_str.split(' ')[1]),1)

      # From controller to switch
      if '6633' == line_list[0].split(' ')[1].split(':')[1]:
        from_controller_map = map_update(from_controller_map, time_number)
      
      # From switch to controller
      else:
        from_swt_map = map_update(from_swt_map, time_number)
   
      # Figure out OFP_TYPE
      ofp_type_str = line_list[3]
      ofp_number = int(ofp_type_str.split(' ')[1])

      if of.OFP_TYPE_LIST[ofp_number] == 'OFPT_FLOW_MOD':
        flow_mod_map = map_update(flow_mod_map, time_number)
      elif of.OFP_TYPE_LIST[ofp_number] == 'OFPT_PACKET_OUT':
        packet_out_map = map_update(packet_out_map, time_number)
      elif of.OFP_TYPE_LIST[ofp_number] == 'OFPT_PACKET_IN':
        packet_in_map = map_update(packet_in_map, time_number)
        

      # Update all_map
      all_map = map_update(all_map, time_number)


  # Save maps
  save_pickled_data(all_map,'all_map','./')
  save_pickled_data(from_controller_map,'from_controller_map','./')
  save_pickled_data(from_swt_map,'from_swt_map','./')

  save_pickled_data(flow_mod_map,'flow_mod_map','./')
  save_pickled_data(packet_out_map,'packet_out_map','./')
  save_pickled_data(packet_in_map,'packet_in_map','./')


def map_update(the_map, key):
  if the_map.has_key(key):
    the_map[key] = the_map[key] + 1
  else:
    the_map[key] = 1

  return the_map


def save_pickled_data(pickled_data, filename, output_dir):
  print '\nSaving Result: %s\n' %(str(filename) + '.p')
  pickle_fd = open(str(output_dir) + str(filename) + '.p','wb')
  pickle.dump(pickled_data,pickle_fd)
  pickle_fd.close()

  return



### START ###
if __name__ == '__main__':
    main()
### end of function ###

