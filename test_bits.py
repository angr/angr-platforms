#!/usr/bin/env python

sr = 0

bitPos = {'T' : 0, 'S' : 1, 'Q' : 8, 'M' : 9}

"""
Set system flags
"""
def set_flags(**kwargs):

	global sr
				
	for bitKey in kwargs:
	
		pos = bitPos[bitKey]
		val = kwargs[bitKey]
		
		if val:
			# Set bit
			sr = sr | (1 << pos)
		else:
			# Clear bit
			sr = sr & ~(1 << pos)		
			
"""
Get system flags
"""
def get_flag(flag):

	global sr

	pos = bitPos[flag]
	
	if (sr >> pos) & 1:
		return 1
	else:
		return 0
		
def test():

	if get_flag('T') != 0:
		print("Fail get T initial")
		
	if get_flag('S') != 0:
		print("Fail get S initial")
		
	if get_flag('Q') != 0:
		print("Fail get Q initial")
		
	if get_flag('M') != 0:
		print("Fail get M initial")
		
	set_flags(T=1)
		
	if get_flag('T') != 1:
		print("Fail set T")
		
	if get_flag('S') != 0:
		print("Fail get S after set")
		
	if get_flag('Q') != 0:
		print("Fail get Q after set")
		
	if get_flag('M') != 0:
		print("Fail get M after set")
		
	set_flags(T=0)
	
	if get_flag('T') != 0:
		print("Fail get T after set 2")
	
	if get_flag('S') != 0:
		print("Fail get S after set 2")
		
	if get_flag('Q') != 0:
		print("Fail get Q after set 2")
		
	if get_flag('M') != 0:
		print("Fail get M after set 2")
		
	set_flags(S=1)
	
	if get_flag('T') != 0:
		print("Fail get T after set 3")
	
	if get_flag('S') != 1:
		print("Fail set S")
		
	if get_flag('Q') != 0:
		print("Fail get Q after set 3")
		
	if get_flag('M') != 0:
		print("Fail get M after set 3")
		
	set_flags(T=1)
	
	if get_flag('T') != 1:
		print("Fail set T 2")
	
	if get_flag('S') != 1:
		print("Fail set S 2")
		
	if get_flag('Q') != 0:
		print("Fail get Q after set 3")
		
	if get_flag('M') != 0:
		print("Fail get M after set 3")
		
	set_flags(T=0,S=0)
	
	if get_flag('T') != 0:
		print("Fail get T after set 4")
	
	if get_flag('S') != 0:
		print("Fail get S after set 4")
		
	if get_flag('Q') != 0:
		print("Fail get Q after set 4")
		
	if get_flag('M') != 0:
		print("Fail get M after set 4")
		
	set_flags(T=1,S=1)
	
	if get_flag('T') != 1:
		print("Fail set T 3")
	
	if get_flag('S') != 1:
		print("Fail set S 3")
		
	if get_flag('Q') != 0:
		print("Fail get Q after set 5")
		
	if get_flag('M') != 0:
		print("Fail get M after set 5")
		
	set_flags(T=0,S=0,Q=1,M=1)
	
	if get_flag('T') != 0:
		print("Fail get T after set 6")
	
	if get_flag('S') != 0:
		print("Fail get S after set 6")
		
	if get_flag('Q') != 1:
		print("Fail get Q after set 6")
		
	if get_flag('M') != 1:
		print("Fail get M after set 6")
		
	set_flags(T=0,S=0,Q=0,M=0)
	
	if get_flag('T') != 0:
		print("Fail get T after set 7")
	
	if get_flag('S') != 0:
		print("Fail get S after set 7")
		
	if get_flag('Q') != 0:
		print("Fail get Q after set 7")
		
	if get_flag('M') != 0:
		print("Fail get M after set 7")
		
	set_flags(T=0,S=1,Q=1,M=1)
	
	if get_flag('T') != 0:
		print("Fail get T after set 7")
	
	if get_flag('S') != 1:
		print("Fail get S after set 8")
		
	if get_flag('Q') != 1:
		print("Fail get Q after set 8")
		
	if get_flag('M') != 1:
		print("Fail get M after set 8")
		
	print(sr)
		
test()
	

