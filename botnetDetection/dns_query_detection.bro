##! Detect DNS queries

@load base/protocols/dns
@load base/frameworks/notice
@load base/frameworks/input

module DNS;
 
export 
{
  redef enum Notice::Type += 
  {
    DNS::SUSPICIOUS,
  };

  const time_interval = 30 mins &redef;
  const dns_threshold = 100 &redef;

  global numRequests = 1.00 &redef;

  event bro_init()
  {
    print "Listening for DNS requests and responses...";

    # this one actually appears second in the output after you ctrl+C
    local q1 = SumStats::Reducer($stream="dns.lookup", $apply=set(SumStats::SUM));
    SumStats::create([$name="DNS Query",
                      $epoch=time_interval,
                      $reducers=set(q1),
                      $epoch_result(ts1: time, q_key: SumStats::Key, q_result: SumStats::Result) =
                      {
                        local q = q_result["dns.lookup"];

                        print fmt("");
                        print fmt("<----------------REQUESTS:---------------->");
                        print fmt("%s sent %d DNS requests within 30 mins", q_key$host, q$num);

                        numRequests = q$sum; # number of requests received
                      },
                      $epoch_finished(ts1: time) =
                      {
                      }
    ]); # end SumStats DNS Query

    # this appears first in the output after ctrl+C
    local r1 = SumStats::Reducer($stream="NOERR", $apply=set(SumStats::UNIQUE));
    SumStats::create([$name="NoError",
                      $epoch=time_interval,
                      $reducers=set(r1),
                      $epoch_result(ts: time, r_key: SumStats::Key, r_result: SumStats::Result) =
                      {
                        local r = r_result["NOERR"];

                        print fmt("");
                        print fmt("<----------------RESPONSES:---------------->");
                        print fmt("%s received %d DNS responses within 30 mins (%d unique).", r_key$host, r$num, r$unique);
                        print fmt("Total DNS responses represent %.0f%% of the total DNS requests.", ((r$num+0.0)/(numRequests+0.0)*100));

                        # if 100 or more requests are found and only 10% are responded to within 30 mins,
                        # then alert that there may be malicious activity
                        if (numRequests >= dns_threshold && r$num/numRequests <= 0.10)
                          print fmt ("%s may have malware (possibly a bot in a botnet)", r_key$host);
                      },
                      $epoch_finished(ts: time) =
                      {
                      }
    ]); # end SumStats NoError
  } # end bro_init

  # this event is called each time a DNS request is found
  event dns_request(c: connection, msg: dns_msg, query: string, qtype: count, qclass: count)
  {
    if ( c$id$resp_p == 53/udp && query != "" )
    {
      # create notice in notice.log about the DNS request from client
      NOTICE([$note=DNS::SUSPICIOUS, $conn=c, $msg=fmt("Query: %s", query),
              $sub=fmt("Query type: %s", qtype), $identifier=cat(c$id$orig_h,c$id$resp_h),
              $suppress_for=20min]);

      # call SumStats so it counts the number of DNS requests
      SumStats::observe("dns.lookup", [$host=c$id$orig_h], [$str=query]);
    } # end if
  } # end event dns_request

  # this event is called each time a DNS response is found
  event dns_query_reply(c: connection, msg: dns_msg, query: string, qtype: count, qclass: count)
  {
    # ensure response code name (rcode_name) field contains a value - used in DNS response
    # ensure response code value is 0, means query completed successfully (DNS response msg = NOERROR)
    if (c$dns?$rcode_name && c$dns$rcode == 0)
    {
      # create notice in notice.log about the successful response
      NOTICE([$note=DNS::SUSPICIOUS, $conn=c, $msg=fmt("Query: %s", query),
              $sub=fmt("Query type: %s", qtype), $identifier=cat(c$id$orig_h,c$id$resp_h),
              $suppress_for=20min]);

      # call SumStats so it counts the number of NOERROR DNS responses
      SumStats::observe("NOERR", [$host=c$id$orig_h], [$str=query]);
    } # end if
  } # end event dns_query_reply
} # end export
