event bro_init() 
{ 
	local ip: addr = 172.16.1.100;
	local s: subnet = 172.16.1.0/24;

	if ( ip in s )
	{
		print "True";
	}
	else
	{
		# A quick way to print multiple things on one line.
		print "False";
	}
} #end init
