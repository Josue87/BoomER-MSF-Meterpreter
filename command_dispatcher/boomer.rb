# -*- coding: binary -*-
require 'rex/post/meterpreter'
require 'readline'

module Rex
module Post
module Meterpreter
module Ui

###
#
# Standard API extension.
#
###
class Console::CommandDispatcher::Boomer


  Klass = Console::CommandDispatcher::Boomer

 

  include Console::CommandDispatcher

  #
  # Initializes an instance of the stdapi command interaction.
  #
  def initialize(shell)
    super
    @functions = {
        "check" => ["boomer_check", true, "Check if an app has a vulnerability (exec: check <app>)"],
        "list_check" => ["list_check", false, "List he applications that allow you to check (exec: list_check)"],
        "autopwn" => ["autopwn", false, "Check all applications (exec: autopwn)"],
        "exploit" => ["boomer_execute", true, "Launch an exploit (exec: exploit <option>)"],
        "list_exploit" => ["list_exploit", false, "List possible exploits (exec: list_exploit)"],
        "info" => ["get_info", true, "Info gathering (exec: info <option> [data]"],
        "list_info" => ["list_info", false, "List possible gathering (exec: list_info)"],
        "help" => ["help", false, "Show this help (exec: help)"]
      }
      @blue = "\e[0;34m"
      @reset = "\e[m"
  
  end

  #
  # Name for this dispatcher
  #
  def name
    'Boomer'
  end

  #
  # List of supported commands.
  #
  def commands
    {
      'start_boomer_console' => "Launch BoomER interactive shell"
    }
  end

@@start_boomer_console_opts = Rex::Parser::Arguments.new(
    '-h' => [false, 'Help banner']
  )

  def start_boomer_console_usage
    print_line('Usage: start_boomer_console')
    print_line
    print_line('Post-Exploitation with BoomER')
    print_line(@@start_boomer_console_opts.usage)
  end

  def cmd_start_boomer_console(*args)
    begin
      autocomplete_list = []
      @functions.each do |key, value|
        autocomplete_list.push(key)
      end
      comp = proc { |s| autocomplete_list.grep(/^#{Regexp.escape(s)}/) }
      Readline.completion_append_character = " "
      Readline.completion_proc = comp
      input = ""
      while input != "exit"
        #print "BoomER >> "
        input = Readline.readline('BoomER >> ', true)
        split_in = input.split
        function = @functions[split_in[0]]
        if function 
          if function[1]
            if split_in[2]
              sp = [split_in[1], split_in[2]]
            else
              sp = [split_in[1]]
            end
            send(function[0], sp)
          else
            eval("#{function[0]}")
          end
        end
      end
    rescue Exception => e
      puts e.message
    end
    result = client.boomer.start_boomer_console()
  end

private

  def cmd_autopwn(*args)
    result = client.boomer.autopwn()
  end

  def boomer_check(input)
    client.boomer.boomer_check(input)
  end

  def autopwn()
    client.boomer.autopwn()
  end

  def list_check()
    client.boomer.list_check()
  end

  def list_exploit()
    client.boomer.list_exploit()
  end

  def list_info()
    client.boomer.list_info()
  end

  def get_info(input)
    client.boomer.get_info(input)
  end

  def help()
    @functions.each do |key, value|
      puts @blue + key + @reset + " - " + value[2]
    end
  end

  def boomer_execute(input)
    obj = client.boomer.boomer_execute(input)
    if (obj && obj[0])
      puts("[*] Process #{obj[1]} created.")
      puts("[*] Channel #{obj[0].cid} created.")
      shell.interact_with_channel(obj[0])
    end
  end

end

end
end
end
end