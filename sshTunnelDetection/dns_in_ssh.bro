##! Find SSH data in DNS traffic

event dns_query_reply(c: connection, msg: dns_msg, query: string, qtype: count, qclass: count)
{
  if(c$id$resp_p == 53/udp && query != "")
  {
    if("=connect" in query)
    {
      print fmt("DNS2TCP SSH Connection Tunnel was detected in %s", c$id$orig_h);
    } # end nested if
  } # end outer if
} # end event
