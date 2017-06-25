use std::{env, fs};
use std::io::{Write};
use std::fs::File;
use std::io::Read;
use std::str;
use std::path::Path;
use std::char;

/*
SDES:
ciphertext = IP^{-1} (fk_2(SW(fk_1(IP(plaintext)))))
plaintext  = IP^{-1} (fk_1(SW(fk_2(IP(plaintext)))))
where:
K_1 = P8(Shift(P10(key)))
K_2 = P8(Shift(Shift(P10(key))))

vector: 10101010
key:    0111111101

byte 1: 00000001  -> 11110100
byte 2: 00100011  -> 00001011

plain                cipher
00000001 00100011 -> 11110100 00001011

=> cargo run [d] <init_key> <init_vector> <original_file> <result_file>
=> cargo run d 0111111101 10101010 file1 file2
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

    //println!("{:?} ==P10=> {:?}", init_key_str, permuted_string);
    permuted_string
}

fn permute_eight(shifted_key: u16) -> String
{
    let init_key_str = format!("{:010b}", shifted_key);
    let mut permuted_chars: Vec<char> = Vec::new();
    let mut permuted_string = String::with_capacity(8);
    let p_eight: [usize;8] = [6,3,7,4,8,5,10,9];

    for x in 0..8 {
        permuted_chars.push(init_key_str.chars().nth(p_eight[x]-1).unwrap() as char);
    }

    for c in &permuted_chars // to avoid 'move' errors, we pass a reference
    {                        // as '&permuted_chars' and dereference '*c'
        permuted_string.push(*c);
    }

    //println!("{:?} ==P8=> {:?}", init_key_str, permuted_string);
    permuted_string
}

fn permute_four(four_bit: u8) -> u8
{
    let mut result: u8 = 0b0000_0000;

    //[2 4 3 1]
    let p_four: [(u8, u8); 4] = [(2, 0b0000_0100),
                                 (0, 0b0000_0001),
                                 (1, 0b0000_0010),
                                 (3, 0b0000_1000)];
    for x in 0..4 {
        result = result << 1;
        if four_bit & (1 << p_four[x].0) == p_four[x].1 { 
            result = result | 1;
        }
    }
    result
}

fn left_shift_one(value: u8) -> u8
{
    let mask: u8 = 31; //0001 1111
    let side = (value <<1) | (value >> (5 - 1));

    mask & side
}

fn left_shift_two(value: u8) -> u8
{
    let mask: u8 = 31; //0001 1111
    let side = (value << 2) | (value >> (5 - 2));

    mask & side
}

fn left_shift_four(value: u8) -> u8 
{
    let mask: u8 = 240; //0000 1111
    let side = (value << 4) | (value >> (4 - 4));

    mask & side
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
    //println!("{:05b} =LS1=> {:05b}_bin", first_half_bits, first_rotated_bits);

    //LS1 on second half: 01100 -> 11000
    let second_half_bits = vec_to_bits(&second_half_str);
    let second_rotated_bits = left_shift_one(second_half_bits);
    //println!("{:05b} =LS1=> {:05b}_bin", second_half_bits, second_rotated_bits);

    let assembled = reassemble(first_rotated_bits, second_rotated_bits);
    //println!("assembled: {:010b}_bin", assembled);

    return (assembled, first_rotated_bits, second_rotated_bits);
}

fn ip(byte: u8) -> u8 {
    // IP    [2,6,3,1,4,8,5,7]
    let mut result: u8 = 0b0000_0000;

    //{6,2,5,7,4,0,3,1}
    let ip: [(u8, u8); 8] = [(6, 0b0100_0000),
                             (2, 0b0000_0100),
                             (5, 0b0010_0000),
                             (7, 0b1000_0000),
                             (4, 0b0001_0000), 
                             (0, 0b0000_0001),
                             (3, 0b0000_1000),
                             (1, 0b0000_0010),];
    for x in 0..8 {
        result = result << 1;
        if byte & (1 << ip[x].0) == ip[x].1 { 
            result = result | 1;
        }
    }
    result
}

fn inverse_ip(byte: u8) -> u8 {
    // IP^-1 [4,1,3,5,7,2,8,6]
    let mut result: u8 = 0b0000_0000;

    //{4,7,5,3,1,6,0,2}
    let ip: [(u8, u8); 8] = [(4, 0b0001_0000),
                             (7, 0b1000_0000),
                             (5, 0b0010_0000),
                             (3, 0b0000_1000),
                             (1, 0b0000_0010), 
                             (6, 0b0100_0000),
                             (0, 0b0000_0001),
                             (2, 0b0000_0100),];
    for x in 0..8 {
        result = result << 1;
        if byte & (1 << ip[x].0) == ip[x].1 { 
            result = result | 1;
        }
    }
    result
}

fn expansion_permutation(four_bit_str: String) -> u8 {
    
    //E/P [4,1,2,3,2,3,4,1]
    //string -> EP -> u8
    //let init_key_str = format!("{:010b}", shifted_key);

    //  do this with bitshifts instead!
    
    let mut permuted_chars: Vec<char> = Vec::new();
    let mut permuted_string = String::with_capacity(8);
    let p_eight: [usize;8] = [4,1,2,3,2,3,4,1];

    for x in 0..8 {
        permuted_chars.push(four_bit_str.chars().nth(p_eight[x]-1).unwrap() as char);
    }

    for c in &permuted_chars // to avoid 'move' errors, we pass a reference
    {                        // as '&permuted_chars' and dereference '*c'
        permuted_string.push(*c);
    }

    //println!("{:?} ==E/P=> {:?}", four_bit_str, permuted_string);
    let ret = vec_to_bits(&permuted_string);
    ret
}

fn expansion_permutation_bits(four_bit: u8) -> u8 {
    
    //E/P [4,1,2,3,2,3,4,1]
    //E/P [3,0,1,2,1,2,3,0]  (-1)
    //E/P [3,0,1,2, 1,2,3,0] split in halves
    //E/P [1,2,3,0, 3,0,1,2] switch halves
    //E/P [0,3,2,1  2,1,0,3] reverse each half
    let mut permuted_bits = 0b0000_0000;
    
    let p_four: [(u8,u8);8] = [(0,0b0000_0001),
                               (3,0b0000_1000),
                               (2,0b0000_0100),
                               (1,0b0000_0010),
                               
                               (2,0b0000_0100),
                               (1,0b0000_0010),
                               (0,0b0000_0001),
                               (3,0b0000_1000)];
                                
    for x in 0..8 {
        permuted_bits = permuted_bits << 1;
        if four_bit & (1 << p_four[x].0) == p_four[x].1 {
            permuted_bits = permuted_bits | 1;
        }
    }
    permuted_bits
}

fn sw(byte: u8) -> u8
{
    let swap = byte.rotate_right(12);
    swap
    //let mut b: u8 = 0b0000_1111;
    //println!("SW: {:08b}", b);
    //println!("SW: {:08b}", b.rotate_right(12));
}

fn fk(eight_bit: u8, sk: u8) -> u8
{
    let mut left_bits: u8 = 0b0000_0000;
    let mut right_bits: u8 = 0b0000_0000;

    //low end (right bits)
    if eight_bit & (1 << 0) == 0b0000_0001 { right_bits = right_bits | 1 << 0; }
    if eight_bit & (1 << 1) == 0b0000_0010 { right_bits = right_bits | 1 << 1; }
    if eight_bit & (1 << 2) == 0b0000_0100 { right_bits = right_bits | 1 << 2; }
    if eight_bit & (1 << 3) == 0b0000_1000 { right_bits = right_bits | 1 << 3; }

    //high end (left bits)
    if eight_bit & (1 << 4) == 0b0001_0000 { left_bits = left_bits | 1 << 0; }
    if eight_bit & (1 << 5) == 0b0010_0000 { left_bits = left_bits | 1 << 1; }
    if eight_bit & (1 << 6) == 0b0100_0000 { left_bits = left_bits | 1 << 2; }
    if eight_bit & (1 << 7) == 0b1000_0000 { left_bits = left_bits | 1 << 3; }

    /*
        1 2 3 4        4 1 2 3 2 3 4 1
        0 1 0 1  =EP=> 1 0 1 0 1 0 1 0
    */

    let exp_perm: u8 = expansion_permutation_bits(right_bits);
    //println!("EP: {:08b}", exp_perm);
    
    /*
        SK: 1 0 1 0 0 1 0 0
        EP: 1 0 1 0 1 0 1 0
        XR: 0 0 0 0 1 1 1 0
     */
     
    let xord = sk ^ exp_perm;
    //println!("xord {:08b}", xord);
    
    // define Sboxes:
    let sbox_zero = [[1,0,3,2],
                     [3,2,1,0],
                     [0,2,1,3],
                     [3,1,3,2]];

    let sbox_one = [[0,1,2,3],
                    [2,0,1,3],
                    [3,0,1,0],
                    [2,1,0,3]];

    /*
        SBOX ACCESS:

        [00][03] => 2-bit <int> => Sbox_Zero's row
        [01][02] => 2-bit <int> => Sbox_Zero's col

        [10][13] => 2-bit <int> => Sbox_One's row
        [11][12] => 2-bit <int> => Sbox_One's col

        Reminder:
        (1 << 0) -> 000001
        (1 << 1) -> 000010
        (1 << 2) -> 000100
        (1 << 3) -> 001000
        (1 << 4) -> 010000
        (1 << 5) -> 100000
    */

    /* * * * * * *
     * SBOX ZERO *
     * * * * * * */
    let mut temp = 0;
    // row:
    if xord & (1 << 4) == 0b0001_0000 { temp = temp | 1 << 0; }
    if xord & (1 << 7) == 0b1000_0000 { temp = temp | 1 << 1; }
    let s_zero_row = temp;
    // column:
    temp = 0; // (reset)
    if xord & (1 << 6) == 0b0100_0000 { temp = temp | 1 << 1; }
    if xord & (1 << 5) == 0b0010_0000 { temp = temp | 1 << 0; }
    let s_zero_col = temp;

    /* * * * * * *
     *  SBOX ONE *
     * * * * * * */
    // row:
    temp = 0;
    if xord & (1 << 3) == 0b0000_1000 {  temp = temp | 1 << 1; }
    if xord & (1 << 0) == 0b0000_0001 {  temp = temp | 1 << 0; }
    let s_one_row = temp;
    // column:
    temp = 0;
    if xord & (1 << 2) == 0b0000_0100 {  temp = temp | 1 << 1; }
    if xord & (1 << 1) == 0b0000_0010 {  temp = temp | 1 << 0; }
    let s_one_col = temp;

    let sbox_zero_val = sbox_zero[s_zero_row][s_zero_col]; //2 bits
    let sbox_one_val = sbox_one[s_one_row][s_one_col]; //2 bits
    //println!("s0: {:02b}, s1: {:02b}", sbox_zero_val, sbox_one_val);

    // join bits obtained from sboxes:
    let mut p_four = 0b0000_0000;

    // set bit 0 
    if sbox_one_val & (1 << 0) == 0b0000_0001 { p_four = p_four | 1 << 0; }
    // set bit 1
    if sbox_one_val & (1 << 1) == 0b0000_0010 { p_four = p_four | 1 << 1; }

    // set bit 2    
    if sbox_zero_val & (1 << 0) == 0b0000_0001 { p_four = p_four | 1 << 2; }
    //set bit 3
    if sbox_zero_val & (1 << 1) == 0b0000_0010 { p_four = p_four | 1 << 3; }

    //println!("joined_bits: {:04b}_bin", p_four);    

    // F(R, SK):

    p_four = permute_four(p_four);
    //println!("P4: {:04b}_bin", p_four);
    //println!("L: {:04b}_bin", left_bits);

    let left_xor_fk = left_bits ^ p_four;
    //println!("X: {:04b}_bin", left_xor_fk);

    //p4 p4 p4 p4 , R R R R (R should be unchanged)
    let byte = left_shift_four(left_xor_fk) | right_bits;
    //println!("{:08b}_bin", byte);

    byte //return
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
    //println!("SUB_KEY_1: {:08b}", cr.key_one);

    // pass halves from triplet to struct
    cr.r_first_half = triplet.1;
    cr.r_second_half = triplet.2;
    //println!("check for halves: {:05b} {:05b}", cr.r_first_half, cr.r_second_half);

    // perform LS2 on both halves and reassemble
    let first_ls_two = left_shift_two(cr.r_first_half);
    let second_ls_two = left_shift_two(cr.r_second_half);

    //println!("{:05b} =LS2=> {:05b}_bin", cr.r_first_half, first_ls_two);
    //println!("{:05b} =LS2=> {:05b}_bin", cr.r_second_half, second_ls_two);

    // Sk2
    cr.key_two = vec_to_bits(&permute_eight(reassemble(first_ls_two, second_ls_two)));

    println!("sk1: {:08b}", cr.key_one);
    println!("sk2: {:08b}\n", cr.key_two);

    match cr.flag {
        'd' => {
            /* * * * * * * *
            * DECRYPTION  *
            * * * * * * * */
            //find out file size
            let file_name = cr.original_file.clone();
            let metadata = fs::metadata(file_name).unwrap();
            let file_size = metadata.len();
            println!("file size: {:?} bytes", file_size);

            //open file
            let mut input_file = File::open(cr.original_file).unwrap();
            let mut writer = File::create(cr.output_file).unwrap();

            //create load file in memory
            let mut contents: Vec<u8> = Vec::new();
            let bytes = input_file.read_to_end(&mut contents).unwrap();
            println!("read: {:?} bytes", bytes);
            drop(input_file); //close

            for x in 0..file_size {

                let cipher_byte = contents[x as usize];

                let mut decrypted_byte = inverse_ip(fk(sw(fk(ip(cipher_byte), cr.key_two)), cr.key_one));

                if x == 0 {
                    //xor the first byte with the init_vec
                    decrypted_byte = decrypted_byte ^ cr.init_vec;
                }
                else
                {
                    //xor subsequent bytes with preceding cipher
                    let prev_cipher_byte = contents[(x-1) as usize];
                    decrypted_byte = decrypted_byte ^ prev_cipher_byte;
                }

                //write to file
                writer.write(&[decrypted_byte]).unwrap();
                //writer.flush();
            }
            drop(writer);
            println!("\ndecryption complete");
        },
        'e' => {
            /* * * * * * * *
            * ENCRYPTION  *
            * * * * * * * */
            //find out file size
            let file_name = cr.original_file.clone();
            let metadata = fs::metadata(file_name).unwrap();
            let file_size = metadata.len();
            println!("file size: {:?} bytes", file_size);

            //open file
            let mut input_file = File::open(cr.original_file).unwrap();
            let mut writer = File::create(cr.output_file).unwrap();

            //create load file in memory
            let mut contents: Vec<u8> = Vec::new();
            let bytes = input_file.read_to_end(&mut contents).unwrap();
            println!("read: {:?} bytes", bytes);
            drop(input_file); //close

            let mut cipher: u8 = 0b0000_0000; //cipher that gets block chained
            for x in 0..file_size {

                let mut plain_byte = contents[x as usize];

                if x == 0 {
                    //xor the first byte with the init_vec
                    plain_byte = plain_byte ^ cr.init_vec;
                }
                else
                {
                    //xor subsequent bytes with preceding cipher
                    plain_byte = plain_byte ^ cipher;
                }

                //generate cipher
                cipher = inverse_ip(fk(sw(fk(ip(plain_byte), cr.key_one)), cr.key_two));

                //write to file
                writer.write(&[cipher]).unwrap();
                //writer.flush();
            }
            drop(writer);
            println!("\nencryption complete");
        },
        _ => println!("no operation mode recognized")
    }

    /*
        SPECIFICATION:
        plaintext:
        [0000_0001] [0010_0011]

        bin_key: 0111111101
        init_vector: 10101010
    
        ciphertext:
        [1111_0100][0000_1011]
    */

    /*println!(":::::encryption:::::");
    //testing first round
    let mut input: u8 = 0b0000_0001;
    //println!("plaintext: {:08b}", input);
    //cbc
    input = input ^ cr.init_vec;
    //println!("cbc byte: {:08b}", input);
    //encrypt
    let cipher = inverse_ip(fk(sw(fk(ip(input), cr.key_one)), cr.key_two));
    
    //testing second round
    let mut input_two: u8 = 0b0010_0011;
    //println!("plaintext: {:08b}", input_two);
    //cbc
    input_two = input_two ^ cipher;
    //println!("cbc byte: {:08b}", input_two);
    //encrypt
    let cipher2 = inverse_ip(fk(sw(fk(ip(input_two), cr.key_one)), cr.key_two));

    println!("first byte: {:08b} -> {:08b}", 0b0000_0001, cipher);
    println!("second byte: {:08b} -> {:08b}", 0b0010_0011, cipher2);
    println!(":::::encryption:::::");*/
}
