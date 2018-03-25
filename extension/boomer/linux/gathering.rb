# -*- coding: binary -*-

require 'rex/post/meterpreter/extensions/boomer/tlv'
require 'rex/post/meterpreter/extensions/boomer/module'
require 'set'

module Rex
module Post
module Meterpreter
module Extensions
module Boomer
module Linux

###
#
# Authors: Josué Encinar && Antonio Marcos
#
###
class Gathering < Module
 def initialize(client)
    super(client)
  end

  def info_suid_sgid(path="")
    request = Packet.create_request('boomer_suid_sgid')
    if path == ""
      path = "/bin"
      puts "Default path "+ path
    end
    request.add_tlv(TLV_TYPE_PYTHON_RESULT, path)
    puts "Checking..."
    result = go_request(request)
    if result[:result]
      r = result[:result]
      if r.include? "Error"
        puts(@red + "[-] " + @reset + r)
        return
      end
      if r.length > 0
        data = r.split("++")
        if data.length > 0
          suid = []
          sgid = []
          if data[0]
            suid = data[0].split(";")
          end
          if data[1]
            sgid = data[1].split(";")
          end
          puts @blue + "-- SUID --" + @reset
          if suid.length > 0
            suid.each do |value|
              puts(@blue + "[*] " + @reset + "#{value}")
            end
          end
          puts @blue + "-- SGID --" + @reset
          if sgid.length > 0
            sgid.each do |value|
              puts(@blue + "[*] " + @reset + "#{value}")
            end
          end
        else
          puts "0.0 Not found"
        end
      else
        puts "0.0 Not found"
      end
      else
        puts "No results..."
    end
  end

end

end; end; end; end; end; end
