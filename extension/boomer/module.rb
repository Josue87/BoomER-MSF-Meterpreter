# -*- coding: binary -*-
module Rex
module Post
module Meterpreter
module Extensions
module Boomer

class Module
  def initialize(client)
    @client = client
    @red = "\e[1;31m"
    @green = "\e[0;32m"
    @blue = "\e[0;34m"
    @reset = "\e[m"
  end

  def go_request(request)
    response = @client.send_request(request)
    result = {
      result: response.get_tlv_value(TLV_TYPE_PYTHON_RESULT),
      stdout: "",
      stderr: ""
    }

    response.each(TLV_TYPE_PYTHON_STDOUT) do |o|
      result[:stdout] << o.value
    end

    response.each(TLV_TYPE_PYTHON_STDERR) do |e|
      result[:stderr] << e.value
    end

    result
  end
end

end
end
end
end
end
