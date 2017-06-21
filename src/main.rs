use std::env;
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
=> cargo run d 0111111101 10101010 file1 file2 //decrypts
=> cargo run d 1010000010 10101010 file1 file2

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
    let p_eight: [usize;8] = [6,3,7,4,8,5,10,9];

    for x in 0..8 {
        permuted_chars.push(init_key_str.chars().nth(p_eight[x]-1).unwrap() as char);
    }

    for c in &permuted_chars // to avoid 'move' errors, we pass a reference
    {                        // as '&permuted_chars' and dereference '*c'
        permuted_string.push(*c);
    }

    println!("{:?} ==P8=> {:?}", init_key_str, permuted_string);
    permuted_string
}

fn permute_four(four_bit: u8) -> u8
{
    let mut result: u8 = 0b0000_0000;
    let p_four: [usize; 4] = [2,0,1,3];
    for x in 0..4 {
        result <<= 1;
        if four_bit & (1 << p_four[x]) == 1{ 
            result |= 1;
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

fn initial_permutation() -> u8 {
    // IP    [2,6,3,1,4,8,5,7]
    2

}

fn inverse_initial_permutation() -> u8 {
    // IP^-1 [4,1,3,5,7,2,8,6]
    2
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

    println!("{:?} ==E/P=> {:?}", four_bit_str, permuted_string);
    let ret = vec_to_bits(&permuted_string);
    ret
}

fn sw(byte: u8) -> String
{
    let swap = byte.rotate_right(12);

    let swap_str = format!("{:08b}", swap);
    swap_str
    //let mut b: u8 = 0b0000_1111;
    //println!("SW: {:08b}", b);
    //println!("SW: {:08b}", b.rotate_right(12));
}

fn fk(eight_bit: String, sk: u8) -> u8
{

    // split byte in string form
    let mut left = eight_bit.clone();
    let right = left.split_off(4).clone();
    let left_bits = vec_to_bits(&left);
    let right_bits = vec_to_bits(&right);
    println!("L: {:?}, R: {:?}", left, right);
    
    let exp_perm: u8 = expansion_permutation(right);
    
    // XOR(eight_bit, SK)
    let xord = sk ^ exp_perm;
    println!("xord {:08b}", xord);

    // [next step might be useless]:
    // create 2D matrix
    /*    
        [00] [01] [02] [03]
        [10] [11] [12] [13]
    */

    /*
    let mut mat = [[0 as u8, 0 as u8, 0 as u8, 0 as u8],
                   [0 as u8, 0 as u8, 0 as u8, 0 as u8]];

    let xord_str = format!("{:08b}", xord);

    // fill first matrix
    for x in 0..3 {
        match xord_str.chars().nth(x).unwrap() {
            '1' => mat[0][x] = 0b0000_0001,
            '0' => mat[0][x] = 0b0000_0000,
            _ => println!("Error on first matrix")
        }
    }

    for x in 4..7 {
        match xord_str.chars().nth(x).unwrap() {
            '1' => mat[1][x-4] = 0b0000_0001,
            '0' => mat[1][x-4] = 0b0000_0000,
            _ => println!("Error on first matrix")
        }
    }
    println!("{:?}", mat);*/
    

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
    */

    /* * * * * * *
     * SBOX ZERO *
     * * * * * * */
     let mut temp = 0;
    // row:
    if xord & (1 << 4) == 1 { temp |= 1 << 0; }
    if xord & (1 << 7) == 1 { temp |= 1 << 1; }
    let s_zero_row = temp;
    // column:
    temp = 0; // (reset)
    if xord & (1 << 6) == 1 { temp |= 1 << 1; }
    if xord & (1 << 5) == 1 { temp |= 1 << 0; }
    let s_zero_col = temp;

    /* * * * * * *
     *  SBOX ONE *
     * * * * * * */
    // row:
    temp = 0;
    if xord & (1 << 3) == 1 {  temp |= 1 << 1; }
    if xord & (1 << 0) == 1 {  temp |= 1 << 0; }
    let s_one_row = temp;
    // column:
    temp = 0;
    if xord & (1 << 2) == 1 {  temp |= 1 << 1; }
    if xord & (1 << 1) == 1 {  temp |= 1 << 0; }
    let s_one_col = temp;

    let sbox_zero_val = sbox_zero[s_zero_row][s_zero_col]; //2 bits
    let sbox_one_val = sbox_one[s_one_row][s_one_col]; //2 bits

    let mut p_four = 0b0000_0000;

    // set bit 0 
    if sbox_zero_val & (1 << 0) == 1{ p_four |= 1 << 0; }
    // set bit 1
    if sbox_zero_val & (1 << 1) == 1{ p_four |= 1 << 1; }

    // set bit 2    
    if sbox_one_val & (1 << 0) == 1{ p_four |= 1 << 2; }
    //set bit 3
    if sbox_one_val & (1 << 1) == 1{ p_four |= 1 << 3; }
    
    // F(R, SK):
    p_four = permute_four(p_four);
    println!("P4: {:04b}_bin", p_four);

    // L + p_four
    //let left_bits = vec_to_bits(&left);
    //let right_bits = vec_to_bits(&right);
    println!("L: {:04b}_bin", left_bits);

    let left_xor_fk = left_bits ^ p_four;
    println!("X: {:04b}_bin", left_xor_fk);

    //p4 p4 p4 p4 , R R R R (R should be intact)
    let byte = left_shift_four(left_xor_fk) | right_bits;
    println!("{:08b}_bin", byte);
    byte
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
     println!(":::::encryption:::::");
     let input = String::from("11110101");
     //let input: u8 = 0b1111_0101;
     let k = fk(input, cr.key_one); //sk1
     let l = fk(sw(k), cr.key_two); //sk2
     println!("\nfk1 byte: {:08b}", k);
     println!("fk2 byte: {:08b}", l);
     println!(":::::encryption:::::");
}