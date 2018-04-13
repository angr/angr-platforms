#!/usr/bin/python

from swpag_client import Team
import os

# This is your team's token
teamToken = "kLWVsbGIhf3R4PjwFS9gkGs6uElQlhJr"

# This may change between CTFs
gameIp = "http://18.219.145.160/"

"""
	Shell We Play a Game
	CSE545 S18 API wrapper / demo
"""
class ProjectCTFAPI():

	__slots__ = ('team', 'debug')
	debug = True # Set to false once you know what you're doing

	"""
	The Team class is your entrypoint into the API
	"""
	def __init__(self, gameIp, teamToken):
	
		self.team = Team(gameIp, teamToken)

	"""
	This returns all of the service ids in the game
	"""
	def getServices(self):

		ids = []
		services = self.team.get_service_list()

		if self.debug:
			print("~" * 5 + " Service List " + "~" * 5)
		
		for s in services:
			ids.append(s['service_id'])

			if self.debug:

				print("Service %s: %s\n\t'%s'" % (s['service_id'], s['service_name'], s['description']))

		return ids
					
	"""
		This returns a list of targets (ports, ips, flag ids) for the given service id
	"""
	def getTargets(self, service):
		
		targets = self.team.get_targets(service)
		
		if self.debug:
			print("~" * 5 + " Targets for service %s " % service + "~" * 5)
			
			for t in targets:
				
				for key in ['hostname','port','flag_id', 'team_name']:
			
					print("%10s : %s" % (key, t[key]))
				print("\n")
			
		return targets
	
	"""
		Submit an individual flag "FLGxxxxxxxx" or list of flags ["FLGxxxxxxxxx", "FLGyyyyyyyy", ...]
	"""
	def submitFlag(self, oneOrMoreFlags):
		
		if not isinstance(oneOrMoreFlags, list):
			oneOrMoreFlags = [oneOrMoreFlags]
			
		status = self.team.submit_flag(oneOrMoreFlags)
		
		if self.debug:
			for i, s in enumerate(status):
				print("Flag %s submission status: %s" % (oneOrMoreFlags[i], s))
		
		return status
		
	# This is just a simple wrapper class
	# See client.py for more methods supported by self.team
	
if __name__ == '__main__':	

	# Initialize API wrapper
	api = ProjectCTFAPI(gameIp, teamToken)
	
	# Get all services in the game
	serviceIds = api.getServices()
	
	# Get all targets for each service
	for service in serviceIds:
		targets = api.getTargets(service)
		
		api.debug = False # change this in the class itself when you know what you're doing

		print("Service %s" % service)
		
		# Exploit all targets
		for target in targets:
		
			print("\tTarget is: %s on %s:%s" % target['team_name'], target['hostname'], target['socket])
		
			# deliver an exploit payload via target['hostname'], target['socket] using flag id target['flag_id'] to get the flag
			# flag = resultOfExploit()
			# api.submitFlag(flag)
			pass
	
		print("Done!")

	
	api.submitFlag("FLG123456789")
	api.submitFlag(["FLG123456799","FLG123456769"])
	