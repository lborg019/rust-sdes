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
cargo run d 0111111101 10101010 file1 file2 //decrypts
cargo run d 1010000010 10101010 file1 file2

key: 01111_11101
01111_11101 =p10=> 11111_10011
[1: 11111] [2: 10011] 
LS1(11111) => 11111
LS1(10011) => 00111
*/

struct Crypto {
    flag: char,
    init_key: u16,
    init_vec: u8,
    init_key_str: String,
    init_vec_str: String,
    key_one: u8,
    key_two: u8,
    r_first_half: u8,
    r_second_half: u8,
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
    //println!("{:?} -> {:010b}_bin", text_key, sixteen_bit);
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
    //println!("{:?}   -> {:08b}_bin", text_vec, eight_bit);
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

fn permute_eight(shifted_key: u16) -> String
{
    let init_key_str = format!("{:010b}", shifted_key);
    let mut permuted_chars: Vec<char> = Vec::new();
    let mut permuted_string = String::with_capacity(8);
    let p_ten: [usize;8] = [6,3,7,4,8,5,10,9];

    for x in 0..8 {
        permuted_chars.push(init_key_str.chars().nth(p_ten[x]-1).unwrap() as char);
    }

    for c in &permuted_chars // to avoid 'move' errors, we pass a reference
    {                        // as '&permuted_chars' and dereference '*c'
        permuted_string.push(*c);
    }

    println!("{:?} ==P8=> {:?}", init_key_str, permuted_string);
    permuted_string
}

fn left_shift_one(value: u8) -> u8
{
    let mask: u8 = 31; //0001 1111
    let side = (value <<1) | (value >> (5 - 1));
    
    return mask & side;
}

fn left_shift_two(value: u8) -> u8
{
    let mask: u8 = 31; //0001 1111
    let side = (value << 2) | (value >> (5 - 2));

    return mask & side;
}

fn reassemble(first_rotated_bits: u8, second_rotated_bits: u8) -> u16
{
    let mut assembled_str = String::new();

    let first_half = format!("{:05b}", first_rotated_bits);
    let second_half = format!("{:05b}", second_rotated_bits);

    assembled_str.push_str(&first_half);
    assembled_str.push_str(&second_half);

    let assembled = key_to_bits(&assembled_str);
    assembled
}

fn circular_left_shift(init_key_str: &String) -> (u16, u8, u8)
{
    let mut first_half_str = init_key_str.clone();
    let second_half_str = first_half_str.split_off(5);

    // e.g.: 10000 01100
    
    //LS1 on first half: 10000 -> 00001
    let first_half_bits = vec_to_bits(&first_half_str);
    let first_rotated_bits = left_shift_one(first_half_bits);
    println!("{:05b} =LS1=> {:05b}_bin", first_half_bits, first_rotated_bits);

    //LS1 on second half: 01100 -> 11000
    let second_half_bits = vec_to_bits(&second_half_str);
    let second_rotated_bits = left_shift_one(second_half_bits);
    println!("{:05b} =LS1=> {:05b}_bin", second_half_bits, second_rotated_bits);

    //reassemble
    /*let mut assembled_str = String::new();
    let first_half = format!("{:05b}", first_rotated_bits);
    let second_half = format!("{:05b}", second_rotated_bits);
    assembled_str.push_str(&first_half);
    assembled_str.push_str(&second_half);*/
    let assembled = reassemble(first_rotated_bits, second_rotated_bits);
    println!("assembled: {:010b}_bin", assembled);

    return (assembled, first_rotated_bits, second_rotated_bits);
}

fn main() {

    if check_arguments() == false
    {
        std::process::exit(1);
    }

    let mut cr = Crypto {
        flag: ' ',
        init_key: 0b0000_0000_0000_0000,
        init_vec: 0b0000_0000,
        init_key_str: String::new(),
        init_vec_str: String::new(),
        key_one: 0b0000_0000,
        key_two: 0b0000_0000,
        r_first_half: 0b0000_0000,
        r_second_half: 0b0000_0000,
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

    /*println!("cr: {:?} {:010b} {:08b} {:?} {:?}", cr.flag, 
                                                  cr.init_key, 
                                                  cr.init_vec,
                                                  cr.original_file,
                                                  cr.output_file);*/

    /* * * * * * * * * *
     * KEY GENERATION *
     * * * * * * * * */
    println!("\n:::key generation:::");
    //P10
    cr.init_key_str = permute_ten(cr.init_key_str);

    // Circular Left Shift (LS-1) on both bit halves of P10
    // triplet: (key, LS1(first), LS1(second))
    let triplet = circular_left_shift(&cr.init_key_str);

    // P8 on the shifted 10 bit key (triplet.0)
    // Sk1
    cr.key_one = vec_to_bits(&permute_eight(triplet.0));
    println!("SUB_KEY_1: {:08b}", cr.key_one);

    // pass halves from triplet to struct
    cr.r_first_half = triplet.1;
    cr.r_second_half = triplet.2;
    //println!("check for halves: {:05b} {:05b}", cr.r_first_half, cr.r_second_half);

    // perform LS2 on both halves and reassemble
    let first_ls_two = left_shift_two(cr.r_first_half);
    let second_ls_two = left_shift_two(cr.r_second_half);

    println!("{:05b} =LS2=> {:05b}_bin", cr.r_first_half, first_ls_two);
    println!("{:05b} =LS2=> {:05b}_bin", cr.r_second_half, second_ls_two);

    // Sk2
    cr.key_two = vec_to_bits(&permute_eight(reassemble(first_ls_two, second_ls_two)));
    println!("SUB_KEY_2: {:08b}", cr.key_two);

    println!(":::key generation:::\n");

    /* * * * * * * *
     * ENCRYPTION  *
     * * * * * * * */

}