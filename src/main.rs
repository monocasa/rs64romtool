extern crate rs64_rom;

use rs64_rom::*;

use std::io;
use std::io::Read;
use std::io::Write;
use std::fs;
use std::process::exit;

fn usage_exit() -> ! {
    let str_args: Vec<String> = std::env::args().collect();
    let exe_name = if str_args.len() > 0 {
        str_args[0].clone()
    } else {
        "rs64tool".to_string()
    };

    eprintln!("Usage: {} SUBCOMMAND ARGS", exe_name);
    eprintln!("\tbuild    BOOTCODE LOADBASE LOADIMG OUTPUT_FILE [EXTRADATA]");
    eprintln!("\t\tcontruct an image from it's constitute parts");
    eprintln!("\tchksum   INPUT_FILE OUTPUT_FILE");
    eprintln!("\t\tsets valid checksums of a ROM");
    eprintln!("\tswap     INPUT_FILE OUTPUT_FILE");
    eprintln!("\t\tswaps the byte ordering of a ROM to native");

    exit(1);
}

fn read_file(filename: &str) -> io::Result<Vec<u8>> {
    let mut file = fs::File::open(filename)?;

    let mut buffer = Vec::new();

    file.read_to_end(&mut buffer)?;

    Ok(buffer)
}

fn write_file(filename: &str, buf: &[u8]) -> io::Result<()> {
    let mut file = fs::File::create(filename)?;

    file.write(buf)?;

    Ok(())
}

fn parse_u32(input_string: &str) -> Result<u32, std::num::ParseIntError> {
	let (base, string) = if input_string.starts_with("0x") {
		(16, &input_string[2..])
	} else {
		(10, input_string)
	};

	u32::from_str_radix(string, base)
}

fn build(args: &[String]) -> io::Result<()> {
    if args.len() != 4 && args.len() != 5 {
        usage_exit();
    }

    let bootcode_filename = &args[0];
    let loadbase_str = &args[1];
    let loadimg_filename = &args[2];
    let output_filename = &args[3];
    let extradata_filename = if args.len() == 5 {
        Some(&args[4])
    } else {
        None
    };

    let loadbase = parse_u32(loadbase_str).unwrap();

    let mut bootcode = read_file(bootcode_filename)?;

    if bootcode.len() != BOOTCODE_LEN as usize {
        return Err(io::Error::new(io::ErrorKind::Other,
            format!("Bootcode is wrong length: {:#x} bytes", bootcode.len())));
    }

    let mut loadimg = read_file(loadimg_filename)?;
    if loadimg.len() > LOAD_LEN as usize {
        return Err(io::Error::new(io::ErrorKind::Other,
            format!("Load image is greater that 1MB: {:#x} bytes", loadimg.len())));
    }

    let residue_len = (LOAD_LEN as usize) - loadimg.len();
    let mut residue: Vec<u8> = vec![0xFF; residue_len];

    let mut extradata = if let Some(filename) = extradata_filename {
        read_file(filename)?
    } else {
        Vec::new()
    };

    let mut header_bytes: Vec<u8> = vec![0; HEADER_LEN as usize];

    let mut rom = Vec::new();
    rom.append(&mut header_bytes);
    rom.append(&mut bootcode);
    rom.append(&mut loadimg);
    rom.append(&mut residue);
    rom.append(&mut extradata);

    let (crc1, crc2) = calculate_cart_checksum(&rom).unwrap();

    let mut rom_header = RomHeader::new();
    rom_header.load_addr = loadbase;
    rom_header.crc1 = crc1;
    rom_header.crc2 = crc2;

    {
        let mut cursor = io::Cursor::new(&mut rom[HEADER_START..HEADER_END]);

        rom_header.serialize(&mut cursor)?;
    }

    write_file(output_filename, &rom)?;

    Ok(())
}

fn chksum(args: &[String]) -> io::Result<()> {
    if args.len() != 2 {
        usage_exit();
    }

    let input_filename = &args[0];
    let output_filename = &args[1];

    let mut buf = read_file(&input_filename)?;

    let orig_swapping = detect_swapping(&buf)
        .ok_or(io::Error::new(io::ErrorKind::Other, "Unable to detect swapping"))?;

    swap_cart_to(ByteSwapping::Native, &mut buf)
        .map_err(|err| io::Error::new(io::ErrorKind::Other,
            format!("Unable to swap to native: {:?}", err)))?;

    let (chksum1, chksum2) = calculate_cart_checksum(&buf)
        .map_err(|err| io::Error::new(io::ErrorKind::Other,
            format!("Unable to calculate checksum: {:?}", err)))?;

    buf[0x10] = (chksum1 >> 24) as u8;
    buf[0x11] = (chksum1 >> 16) as u8;
    buf[0x12] = (chksum1 >>  8) as u8;
    buf[0x13] = (chksum1 >>  0) as u8;
    buf[0x14] = (chksum2 >> 24) as u8;
    buf[0x15] = (chksum2 >> 16) as u8;
    buf[0x16] = (chksum2 >>  8) as u8;
    buf[0x17] = (chksum2 >>  0) as u8;

    swap_cart_to(orig_swapping, &mut buf)
        .map_err(|err| io::Error::new(io::ErrorKind::Other,
            format!("Unable to swap to original: {:?}", err)))?;

    write_file(&output_filename, &buf)?;

    Ok(())
}

fn swap(args: &[String]) -> io::Result<()> {
    if args.len() != 2 {
        usage_exit();
    }

    let input_filename = &args[0];
    let output_filename = &args[1];

    let mut buf = read_file(&input_filename)?;

    swap_cart_to(ByteSwapping::Native, &mut buf)?;

    write_file(&output_filename, &buf)?;

    Ok(())
}

fn main() {
    let full_args: Vec<String> = std::env::args().collect();

    if full_args.len() < 2 {
        usage_exit();
    }

    let subcommand = full_args[1].clone();

    let sub_args = &full_args[2..];

    match subcommand.as_ref() {
        "build"  => build(sub_args),
        "chksum" => chksum(sub_args),
        "swap"   => swap(sub_args),
        _ => {
            eprintln!("Error:  Unknown subcommand: \"{}\"", subcommand);
            usage_exit();
        }
    }.unwrap();
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse() {
        assert_eq!(parse_u32("0"), Ok(0));
        assert_eq!(parse_u32("0x0"), Ok(0));

        assert_eq!(parse_u32("0xFFFFFFFF"), Ok(0xFFFFFFFF));

        assert_eq!(parse_u32("12345678"), Ok(12345678));

        assert_eq!(parse_u32("0x12345678"), Ok(0x12345678));
    }
}