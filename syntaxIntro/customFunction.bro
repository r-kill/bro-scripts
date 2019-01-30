function inSubnet(ip: set[addr], s: subnet): string
{
  for(address in ip)
  {
    if(address in s)
    {
      print address;
    }
    else
    {
      print fmt("IP address <%s> is not in subnet", address);
    } #end if else
  } #end for
  return "";
} #end function

event bro_init() 
{ 
  local ip: set[addr] = {172.16.1.1, 172.16.1.2, 172.16.1.3, 172.16.1.4};
  local s: subnet = 172.16.1.0/24;
	
  inSubnet(ip, s);
} # end init
