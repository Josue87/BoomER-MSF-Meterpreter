# -*- coding: binary -*-

require 'rex/post/meterpreter/extensions/boomer/tlv'
require 'rex/post/meterpreter/extensions/boomer/module'
require 'set'

module Rex
module Post
module Meterpreter
module Extensions
module Boomer
module Windows

###
#
# Authors: Josué Encinar && Antonio Marcos
#
###
class Gathering < Module
 def initialize(client)
    super(client)
  end

  def get_autoelevate(path="")
    request = Packet.create_request('boomer_auto_elevate')
    if path == ""
      path = "C:\\windows\\system32"
      puts "Default path "+ path
    end
    request.add_tlv(TLV_TYPE_PYTHON_RESULT, path)
    result = go_request(request)

    if result[:result]
      r = result[:result]
      if r.include? "Error"
        puts(@red + "[-] " + @reset + r)
        return
      end
      if r.length > 0
        data = r.split(";")
        if data
          data.each do |value|
            puts(@blue + "[*] " + @reset + "#{value}")
          end
        end
     
      end
    else
      puts "No results..."
    end
    
  end

end

end; end; end; end; end; end
