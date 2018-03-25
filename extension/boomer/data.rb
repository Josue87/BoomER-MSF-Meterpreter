module Rex
module Post
module Meterpreter
module Extensions
module Boomer

EXPLOITS = {
        "screen4.5" =>  {
          "function" => "@linux_exploit.screenploit",
          "os" => "linux",
          "description" => "Get a root shell exploiting vulnerability in 'Screen 4.5'"
        }
      }

GATHERING = {
        "auto_elevate" =>  {
          "function" => "@windows_gathering.get_autoelevate",
          "os" => "windows",
          "description" => "Get Apps whit auto elevate",
          "examples" => ["info auto_elevate", "info auto_elevate C:\\Windows", "info auto_elevate C:\\Windows\\system32"]
        },
        "suid_sgid" => {
          "function" => "@linux_gathering.info_suid_sgid",
          "os" => "linux",
          "description" => "Get Apps whit SUID or SGID flags",
          "examples" => ["info suid_sgid", "info suid_sgid /bin", "info suid_sgid /etc"]
        }
      }

DATA_CHECK = {
        'screen' => {
          'command' => 'screen --version',
          'versions' => [{"4.05" => 'Privilege Escalation -> To get a RootShell try to run: exploit screen4.5'}],
          "os" => "linux",
          "description" => "Check app screen"
        },
        'jad' => {
          'command' => 'jad',
          'versions' => [{"1.5.8e" => 'Vulnerable to stack-based Buffer overflow'}],
          "os" => "linux",
          "description" => "Check app Jad"
        }
      }

end
end
end
end
end