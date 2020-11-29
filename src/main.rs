use std::io::{self, Write};
use crypto::aes::{cbc_decryptor, cbc_encryptor};
use crypto::{symmetriccipher, buffer};
use crypto::buffer::{ ReadBuffer, WriteBuffer, BufferResult };
use rpassword::read_password;
use std::collections::HashMap;
use crypto::blockmodes::PkcsPadding;
use base64;
use rusqlite;

const MASTER: &str = "test123";

#[derive(Debug)]
pub struct Account {
    account_name: String,
    url: String,
    username: String,
    password: String
}

impl Account {
    pub fn new(account_name: String, url: String, username: String, password:String) -> Account {
        Account {
            account_name,
            url,
            username,
            password
        }
    }

    pub fn decrypt_pass(&mut self) {
        self.password = decrypt(&self.password).expect("Decryption failed");
    }
}

/// Take input from the user
fn get_input() -> String {
    let mut buffer = String::new();
    io::stdin().read_line(&mut  buffer).expect("Failed");
    buffer
}

/// Takes a borrowed String and encrypts it using the master password. A Result containing a base64 enocded String.
fn encrypt(data: &String) -> Result<String, symmetriccipher::SymmetricCipherError> {
    let mut encryptor = cbc_encryptor(
        crypto::aes::KeySize::KeySize256,
         MASTER.as_bytes(),
          &[0 as u8; 16],
           PkcsPadding
        );

    let mut final_result = Vec::<u8>::new();
    let mut read_buffer = buffer::RefReadBuffer::new(data.as_bytes());
    let mut buffer = [0; 4096];
    let mut write_buffer = buffer::RefWriteBuffer::new(&mut buffer);

    loop {
        let result = encryptor.encrypt(&mut read_buffer, &mut write_buffer, true)?;

        final_result.extend(write_buffer.take_read_buffer().take_remaining().iter().map(|&i| i));

        match result {
            BufferResult::BufferUnderflow => break,
            BufferResult::BufferOverflow => { }
        }
    }

    // Encode bytes into base64 encoded String
    let final_result = base64::encode(&final_result);
    Ok(final_result)
}

/// Decrypts a base64 encoded String.
fn decrypt(encrypted_data: &String) -> Result<String, symmetriccipher::SymmetricCipherError> {
    let mut decryptor = cbc_decryptor(
            crypto::aes::KeySize::KeySize256,
            MASTER.as_bytes(),
            &[0 as u8; 16],
            PkcsPadding);

    // Decode base64 encoded String into bytes
    let encrypted_bytes = base64::decode(encrypted_data).unwrap();

    let mut final_result = Vec::<u8>::new();
    let mut read_buffer = buffer::RefReadBuffer::new(&encrypted_bytes);
    let mut buffer = [0; 4096];
    let mut write_buffer = buffer::RefWriteBuffer::new(&mut buffer);

    loop {
        let result = decryptor.decrypt(&mut read_buffer, &mut write_buffer, true)?;
        final_result.extend(write_buffer.take_read_buffer().take_remaining().iter().map(|&i| i));
        match result {
            BufferResult::BufferUnderflow => break,
            BufferResult::BufferOverflow => { }
        }
    }

    let final_result = String::from_utf8(final_result).unwrap();
    Ok(final_result)
}

fn main() -> std::io::Result<()> {
    let conn = rusqlite::Connection::open("./padlock.db").expect("Failed to connect to DB");

    conn.execute("create table if not exists accounts (
             id integer primary key,
             account_name varchar(255) not null,
             username varchar(255) not null,
             password varchar(255) not null,
             url varchar(255) not null
         )", rusqlite::NO_PARAMS).expect("DB initialize script failed.");

    println!("Welcome to Padlock!");
    print!("Please enter the master password:  ");
    io::stdout().flush().unwrap();

    loop {
        if read_password()?.trim() != MASTER {
            println!("Invalid master password");
            print!("Please enter the correct master passord:  ");
            io::stdout().flush().unwrap();
        } else {
            break;
        }
    }

    loop {
        println!("\n------------------MENU------------------");
        println!("Please select an option:");
        println!("1) Add a new account password");
        println!("2) Lookup an existing account password");
        println!("Q) Exit application");
        let choice = get_input();

        match choice.as_str().trim() {
            "1" => {
                print!("Enter the name of the account:  ");
                io::stdout().flush().unwrap();
                let account = get_input();
                print!("Enter the account url:  ");
                io::stdout().flush().unwrap();
                let url = get_input();
                print!("Enter the email/username for this account:  ");
                io::stdout().flush().unwrap();
                let user = get_input();
                print!("Enter the password for this account:  ");
                io::stdout().flush().unwrap();
                let pwd = read_password()?;

                let pwd = encrypt(&pwd).ok().unwrap();
                let data = Account::new(account, url, user, pwd);

                match conn.execute(
            "INSERT INTO accounts (account_name, url, username, password) values (?1, ?2, ?3, ?4)",
            &[&data.account_name, &data.url, &data.username, &data.password],
                ) {
                    Ok(_) => println!("Account successfully save to DB"),
                    Err(e) => println!("Error: {}", e)
                }
            },
            "2" => {
                print!("Enter the account name that you want to lookup:  ");
                io::stdout().flush().unwrap();
                let account = get_input();
                let mut stmt = conn.prepare("select a.account_name, a.url, a.username, a.password from accounts a where a.account_name = :account").unwrap();
                let accounts_iter = stmt.query_map_named(&[(":account", &account)], |row| {
                    let mut acc = Account::new(
                        row.get(0)?,
                        row.get(1)?,
                        row.get(2)?,
                        row.get(3)?
                    );
                    acc.decrypt_pass();
                    Ok(acc)
                }).expect("Failed to fetch data from DB");

                for acc in accounts_iter {
                    println!("Found Account: {:?}", acc.unwrap());
                }
            },
            "q" | "Q" => break,
            _ => {
                println!("Invalid option");
                continue;
            }
        }
    }

    Ok(())
}
