# nuage_hackathon
Code submission for Nuage hackathon held at Centennial Campus on 02-23-2015

####Requirement
	* Create a program to implement [ACL(Access Control List)](http://en.wikipedia.org/wiki/Access_control_list).
	* The program should have feature to add, store multiple ACLs.
	* Each ACL can have multiple rules based on various values of fields such as source IP, destination IP, protocol used, source port, destination port, etc.
	* The rules should support wildcard entries.
	* Incoming packets should be checked against all ACLs and appropriate decision(forward/discard should be taken).