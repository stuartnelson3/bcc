class KprobeOutput
  attr_reader :fn, :src_ip, :dst_ip, :type

  FN_TO_NAME = {
    1 => 'netif_receive_skb',
    2 => 'ip_rcv',
    3 => 'ip_forward',
    4 => 'ip_output',
    5 => 'ip_finish_output',
    6 => 'ip_finish_output2',
    7 => 'icmp_send',
  }

  def initialize(fn, src_ip, dst_ip, type)
    @fn = fn
    @src_ip = src_ip
    @dst_ip = dst_ip
    @type = type == 0 ? :syn : :syn_ack
  end

  def fn_name
    FN_TO_NAME[fn]
  end

end

class OutputSequence
  attr_reader :outputs

  def initialize(outputs)
    if !outputs.map(&:type).all?
      raise ArgumentError, 'kprobe outputs have mixed syn and syn-ack types'
    end

    @outputs = outputs
  end

  def type
    outputs.first.type
  end

  def src_ip
    outputs.first.src_ip
  end

  def dst_ip
    outputs.first.dst_ip
  end

  def has_drops?
    !(seq_one? || seq_two?)
  end

  def last_fn
    outputs.last.fn_name
  end

  SEQUENCE_ONE = [4, 5, 6, 1, 2, 3, 4, 5, 6]
  SEQUENCE_TWO = [2, 3, 4, 5, 6, 2]
  # A full sequence may be repeated multiple times within a single ack or
  # syn-ack transmission.
  # Additionally, it appears full syn and syn-ack messages can follow either
  # function sequence.
  def seq_one?
    fns == SEQUENCE_ONE * (fns.length / SEQUENCE_ONE.length)
  end

  def seq_two?
    fns == SEQUENCE_TWO * (fns.length / SEQUENCE_TWO.length)
  end

  def fns
    outputs.map(&:fn)
  end
end

output = File.readlines('output.txt').map do |line|
  s = line.split
  KprobeOutput.new(s[0].to_i, s[1], s[2], s[3].to_i)
end

grouped = output.group_by {|k| "#{k.src_ip} #{k.dst_ip}" }

output_sequences = grouped.each.map do |_,v|
  OutputSequence.new(v)
end

drop_sequences = output_sequences.select(&:has_drops?)

drop_length = drop_sequences.length

if drop_length == 0
  puts "no drops"
end

drop_percent = (drop_length.to_f / output_sequences.length * 100).round(2)

puts "total packets: #{output_sequences.length}"
puts "total drops: #{drop_length} (#{drop_percent}%)"

drop_sequences.each do |seq|
  puts "drop #{seq.src_ip} #{seq.dst_ip} #{seq.fns} #{seq.type}"
end
