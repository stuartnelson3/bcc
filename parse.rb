class KprobeOutput
  attr_reader :ts, :fn, :src_ip, :dst_ip, :type

  FN_TO_NAME = {
    1 => 'netif_receive_skb',
    2 => 'ip_rcv',
    3 => 'ip_forward',
    4 => 'ip_output',
    5 => 'ip_finish_output',
    6 => 'ip_finish_output2',
    7 => 'icmp_send',
    8 => 'ip_local_deliver',
  }

  def initialize(ts, fn, src_ip, dst_ip, type)
    @ts = ts
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
    !(seq_one? || seq_two? || seq_three? || seq_four?)
  end

  def last_fn
    outputs.last.fn_name
  end

  # http://lxr.free-electrons.com/source/net/core/dev.c?v=4.4#L3806
  # These seem to be the three main patterns I'm seeing. There's A large switch
  # statement on rx_handler at 3891 that probably is the cause of looping
  # through the process starting at fn 2.
  SEQUENCE_ONE = [4, 5, 6, 1, 2, 3, 4, 5, 6]
  SEQUENCE_TWO = [2, 3, 4, 5, 6]
  SEQUENCE_THREE = [2, 3, 4, 5, 6, 2]
  SEQUENCE_FOUR = [2, 2, 3, 4, 5, 6]
  # A full sequence may be repeated multiple times within a single ack or
  # syn-ack transmission.
  # Additionally, it appears full syn and syn-ack messages can follow either
  # function sequence.
  def seq_one?
    fns == SEQUENCE_ONE * (fns.length / SEQUENCE_ONE.length)
  end

  def seq_two?
    seq = SEQUENCE_TWO * (fns.length / SEQUENCE_TWO.length)
    seq_capped = seq + [2]
    fns == seq || fns == seq_capped
  end

  def seq_three?
    fns == SEQUENCE_THREE * (fns.length / SEQUENCE_THREE.length)
  end

  def seq_four?
    fns == SEQUENCE_FOUR * (fns.length / SEQUENCE_FOUR.length)
  end

  def fns
    outputs.map(&:fn)
  end
end


# Begin scripty part

output_file = 'output3.txt'

file = File.open(output_file, 'r')
i = 0
output = []
while i < 1_000_000
  i += 1
  line = file.gets
  s = line.split
  output << KprobeOutput.new(s[0].to_i, s[1], s[2], s[3], s[4].to_i)
end
file.close

grouped = output.group_by {|k| "#{k.src_ip} #{k.dst_ip}" }

output_sequences = grouped.values.lazy.flat_map do |kprobes|
  kprobes.each_with_index.each_with_object([[]]) do |(kp, i), a|
    unless kprobes[i+1]
      a.last << kp
      next
    end

    # Chunk by 50ms segments (ts is in microseconds)
    if (kp.ts - kprobes[i+1].ts).abs < 500
      a.last << kp
    else
      a << [kp]
    end
  end
end.map do |v|
  OutputSequence.new(v)
end.force

# This gives all the found sequences. Figure out if this looks right:
# - Are the sequences we're expecting the ones we're getting?
grouped_sequences = output_sequences.group_by {|e| e.fns }
sequence_percentage = grouped_sequences.each_with_object({}) do |(k, v), h|
  h[k] = (v.length.to_f / output_sequences.length * 100).round(5)
end.sort_by {|k, v| v }


NAME_TO_FN = {
  'netif_receive_skb' => 1,
  'ip_rcv' => 2,
  'ip_forward' => 3,
  'ip_output' => 4,
  'ip_finish_output' => 5,
  'ip_finish_output2' => 6,
  'icmp_send' => 7,
  'ip_local_deliver' => 8,
}

# Print out the sequences and their occurence percentage
format_str = "%-16s %s\n"
printf(format_str, "SEQUENCE", "PERCENTAGE")
sequence_percentage.each { |(seq, pc)| printf(format_str, seq.map{|s| NAME_TO_FN[s] }.join, pc) }

# drop_sequences = output_sequences.select(&:has_drops?)
#
# drop_length = drop_sequences.length
#
# if drop_length == 0
#   puts "no drops"
# end
#
# drop_percent = (drop_length.to_f / output_sequences.length * 100).round(2)
#
# puts "total packets: #{output_sequences.length}"
# puts "total drops: #{drop_length} (#{drop_percent}%)"
#
# drop_sequences.each do |seq|
#   puts "drop #{seq.src_ip} #{seq.dst_ip} #{seq.fns} #{seq.type}"
# end
