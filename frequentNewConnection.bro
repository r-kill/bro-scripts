##! This script tracks new connections to the host and determines the time between
##! subsequent packets received from the connections.

@load base/frameworks/notice
@load base/protocols/conn

# global variable - table of time indexed by IP address of source
global src: table[addr] of time;

export 
{
  redef enum Notice::Type += 
  {
		# Generated if new connections are being attempted to the server
		New_Connection
  };
}

event new_connection(c: connection)
{
  # ensure source and destination are not the same IP address
  if(c$id$orig_h == 192.168.199.1 && c$id$resp_h != 192.168.199.1)
  {
    # check if IP is in table already
    if(c$id$orig_h !in src)
    {
      # add time of new connection indexed by IP address
      src[c$id$orig_h] = network_time();
    }
    else
    {
      # print time since last packet if IP address is in table
      # get absolute value because calculation produces a negative value
      #	showing how many seconds it has been since initial connection attempt
      print fmt("%s connection %.4f seconds ago", c$id$orig_h, |(src[c$id$orig_h] - network_time())|);
					
      # set time to value of network_time() so that the time between each
      #	packet is calculated
      # removing this statement will cause the program to find the time between
      #	the first packet seen and the most recent packet seen
      src[c$id$orig_h] = network_time();
    } # end if else
		
    NOTICE([$note=New_Connection, $conn=c]);
  } # end if
} # end event
