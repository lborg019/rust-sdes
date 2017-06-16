use std::env;
use std::str;
use std::path::Path;
use std::char;

/*
vector: 10101010
key:    0111111101

byte 1: 00000001  -> 11110100
byte 2: 00100011  -> 00001011

plain                cipher
00000001 00100011 -> 11110100 00001011

% cargo run [-d] <init_key> <init_vector> <original_file> <result_file>
cargo run -d 0111111101 10101010 file1 file2 //decrypts

*/

struct Crypto {
    flag: char,
    init_key: u16,
    init_vec: u8,
    init_key_str: String,
    init_vec_str: String,
    original_file: String,
    output_file: String
}

fn check_flag(index: usize) -> bool
{
    let flag = env::args().nth(index).unwrap();
    match flag.as_ref() {
        "d" => true,
        _ => {
            println!("incorrect flag");
            false
        }
    }
}

fn check_key(index: usize) -> bool
{
    let key = env::args().nth(index).unwrap();
    let key_len = key.len();
    let mut count = 0;

    println!("init_key: {:?}", key);

    match key_len {
        10 => {
            for c in key.chars()
            {
                match c {
                    '0' => continue,
                    '1' => continue,
                    _ =>
                    {
                        println!("init key must be binary (0s and 1s only)");
                        count = count + 1;
                    }
                }
            }

            match count {
                0 => true,
                _ => false
            }
        },
        _ => {
            println!("init key must be 10 bits long!");
            false
        }
    }
}

fn check_vector(index: usize) -> bool
{
    let vector = env::args().nth(index).unwrap();
    let vector_len = vector.len();
    let mut count = 0;

    println!("init_vec: {:?}", vector);

    match vector_len {
        8 => {
            for c in vector.chars()
            {
                match c {
                    '0' => continue,
                    '1' => continue,
                    _ =>
                    {
                        println!("vector must be binary (0s and 1s only)");
                        count = count + 1;
                    }
                }
            }

            match count {
                0 => true,
                _ => false
            }
        },
        _ => {
            println!("init key must be 8 bits long!");
            false
        }
    }
}

fn check_file(index: usize) -> bool
{
    let mut path = String::from("./");
    let file_name = String::from(env::args().nth(index).unwrap());
    path.push_str(&file_name);
    let check = Path::new(&path).is_file();
    match check
    {
        true => {
            println!("file    : {:?}", file_name);
            true
        },
        _ => {
            println!("file not found");
            false
        }
    }
}

fn check_arguments() -> bool
{
    let args_amount = env::args().len() - 1;
    match args_amount {
        4 => {
            println!("encryption mode");
            match check_key(1) //key is arg #1
            {
                true => {
                    match check_vector(2)
                    {
                        true => {
                            match check_file(3)
                            {
                                true => true,
                                _ => false
                            }
                        },
                        _ => false
                    } 
                },
                _ => false
            }
        },
        5 => {
            println!("decryption mode");
            match check_flag(1) //flag is arg #1
            {
                true => {
                    match check_key(2)
                    {
                        true => match check_vector(3)
                        {
                            true => {
                                match check_file(4)
                                {
                                    true => true,
                                    _ => false
                                }
                            },
                            _ => false
                        },
                        _ => false
                    }
                },
                _ => false
            }

        },
        _ => { 
            println!("incorrect amount of arguments");
            println!("cargo run [d] <init_key> <init_vector> <original_file> <result_file>");
            false
        },
    }
}

fn key_to_bits(key_string: &String) -> u16
{
    let text_key = key_string;
    let mut sixteen_bit: u16 = 0b0000_0000_0000_0000;
    
    for c in text_key.chars()
    {
        match c {
            '0' => {
                sixteen_bit = sixteen_bit.rotate_left(1);
            }
            '1' => {
                sixteen_bit |= 0b1000_0000_0000_0000;
                sixteen_bit = sixteen_bit.rotate_left(1);
            }
            _ => println!("failed to convert key to bits"),
        }
    }
    //sixteen_bit.leading_zeros());
    println!("{:?} -> {:010b}_bin", text_key, sixteen_bit);
    sixteen_bit
}

fn vec_to_bits(vec_string: &String) -> u8
{
    // u8 = 0b0000_0000;
    let text_vec = vec_string;
    let mut eight_bit: u8 = 0b0000_0000;

    for c in text_vec.chars()
    {
        match c {
            '0' => {
                eight_bit = eight_bit.rotate_left(1);
            },
            '1' => {
                eight_bit |= 0b1000_0000; //set first bit
                eight_bit = eight_bit.rotate_left(1);
            },
            _ => println!("failed to convert vector to bits"),
        }
    }
    println!("{:?}   -> {:08b}_bin", text_vec, eight_bit);
    eight_bit
}

fn permute_ten(init_key_str: String) -> String
{    
    let mut permuted_chars: Vec<char> = Vec::new();
    let mut permuted_string = String::with_capacity(10);
    let p_ten: [usize;10] = [3,5,2,7,4,10,1,9,8,6];

    for x in 0..10 {
        permuted_chars.push(init_key_str.chars().nth(p_ten[x]-1).unwrap() as char);
    }

    for c in &permuted_chars // to avoid 'move' errors, we pass a reference
    {                        // as '&permuted_chars' and dereference '*c'
        permuted_string.push(*c);
    }

    println!("{:?} ==P10=> {:?}", init_key_str, permuted_string);
    permuted_string
}

fn main() {

    if check_arguments() == false
    {
        std::process::exit(1);
    }

    let mut cr = Crypto {
        flag: ' ',
        init_key: 0b0000000000000000,
        init_vec: 0b00000000,
        init_key_str: String::new(),
        init_vec_str: String::new(),
        original_file: String::new(),
        output_file: String::new()
    };

    let args_amount = env::args().len() - 1;
    match args_amount {
        4 => {
            cr.flag='e';
            cr.init_key_str = String::from(env::args().nth(1).unwrap());
            cr.init_vec_str = String::from(env::args().nth(2).unwrap());
            cr.init_key = key_to_bits(&cr.init_key_str);
            cr.init_vec = vec_to_bits(&cr.init_vec_str);
            cr.original_file = env::args().nth(3).unwrap();
            cr.output_file = env::args().nth(4).unwrap();
        },
        5 => {
            cr.flag = 'd';
            cr.init_key_str = String::from(env::args().nth(2).unwrap());
            cr.init_vec_str = String::from(env::args().nth(3).unwrap());
            cr.init_key = key_to_bits(&cr.init_key_str);
            cr.init_vec = vec_to_bits(&cr.init_vec_str);
            cr.original_file = env::args().nth(4).unwrap();
            cr.output_file = env::args().nth(5).unwrap();
        }
        _ => std::process::exit(1)
    }

    println!("cr: {:?} {:010b} {:08b} {:?} {:?}", cr.flag, 
                                                  cr.init_key, 
                                                  cr.init_vec,
                                                  cr.original_file,
                                                  cr.output_file);

    /* * * * * * * * * *
     * KEY GENERATION *
     * * * * * * * * */

    //P10
    permute_ten(cr.init_key_str);

    //Circular Left Shift (LS-1) on first 5 bits of P10

    //Circular Left Shift (LS-1) on last 5 bits of P10

    //P8 (picks and permutes 8 out of 10 bits) = K1

}
