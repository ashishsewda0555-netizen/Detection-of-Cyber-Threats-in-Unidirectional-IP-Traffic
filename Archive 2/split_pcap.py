import os
import struct

def split_pcap_binary(input_file, chunk_size=500000):
    if not os.path.exists(input_file):
        print(f"Error: Could not find {input_file}")
        return

    output_prefix = input_file.replace(".pcap", "_chunk")
    print(f"Splitting {input_file} into chunks of {chunk_size} packets using Raw Binary I/O...")

    try:
        with open(input_file, 'rb') as f_in:
            # PCAP global header is exactly 24 bytes
            global_header = f_in.read(24)
            if len(global_header) < 24:
                print("Error: Invalid PCAP file (too small)")
                return

            # Check endianness from magic number
            magic = global_header[:4]
            if magic in (b'\xa1\xb2\xc3\xd4', b'\xa1\xb2\x3c\x4d'):
                endian = '>'
            elif magic in (b'\xd4\xc3\xb2\xa1', b'\x4d\x3c\xb2\xa1'):
                endian = '<'
            else:
                print("Error: Unknown PCAP magic number.")
                return

            chunk_num = 1
            packet_count = 0
            f_out = None
            
            while True:
                if packet_count % chunk_size == 0:
                    if f_out:
                        f_out.close()
                    out_name = f"{output_prefix}_{chunk_num:02d}.pcap"
                    print(f"--> Writing to {out_name}...")
                    f_out = open(out_name, 'wb')
                    f_out.write(global_header)
                    chunk_num += 1

                # Read packet header (16 bytes)
                pkt_header = f_in.read(16)
                if not pkt_header or len(pkt_header) < 16:
                    break # EOF

                # Parse included length (incl_len is at offset 8, 4 bytes)
                incl_len = struct.unpack(f"{endian}I", pkt_header[8:12])[0]

                # Read packet data
                pkt_data = f_in.read(incl_len)
                if len(pkt_data) < incl_len:
                    break # Unexpected EOF
                
                # Write to current chunk
                f_out.write(pkt_header)
                f_out.write(pkt_data)
                
                packet_count += 1
            
            if f_out:
                f_out.close()
                
        print(f"\nSuccess! Processed {packet_count:,} packets total.")
        print(f"You can now use one of the chunks (e.g., {output_prefix}_01.pcap) for Phase 1.")
        
    except Exception as e:
        print(f"An error occurred: {e}")

if __name__ == "__main__":
    split_pcap_binary("spoofed_flood_01.pcap", chunk_size=500000)
