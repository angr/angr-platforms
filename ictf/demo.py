#!/usr/bin/python

from swpag_client import Team

"""
	Shell We Play a Game Attack-Defense CTF
	CSE545 S18 API wrapper / demo
"""
class ProjectCTFAPI():

	# This is just a simple wrapper class
	# See client.py for more methods supported by self.team

	__slots__ = ('team', 'debug')

	"""
		The Team class is your entrypoint into the API
	"""
	def __init__(self, gameIp, teamToken):
		self.debug = False
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
	
if __name__ == '__main__':	

	# This is your team's token
	teamToken = "kLWVsbGIhf3R4PjwFS9gkGs6uElQlhJr"
	
	if teamToken == "":
		raise RuntimeError("You need to specify your team token.")

	# This may change between CTFs
	gameIp = "http://18.219.145.160/"

	# Initialize API wrapper
	api = ProjectCTFAPI(gameIp, teamToken)
	
	# Remove this line once you know what you're doing
	api.debug = True 
	
	import IPython
	# lots of code
	# even more code
	IPython.embed()
	
	# Get all services in the game
	serviceIds = api.getServices()
	
	# Get all targets for each service
	for service in serviceIds:
		targets = api.getTargets(service)
		
		# targets contains the hostname and port of each team's service
		
		# Now you know what to hack!
		# Send some exploits and get some flags!
	
		# Submit a flag (hopefully not this one)!
		api.submitFlag("FLG123456789")