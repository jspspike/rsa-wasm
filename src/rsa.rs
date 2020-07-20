use wasm_bindgen::prelude::*;
use rand::rngs::OsRng;
use rsa::{PublicKey, RSAPublicKey, PaddingScheme};
use base64;


#[wasm_bindgen]
pub fn public_encrypt(key: &str, text: &str) -> Result<String, JsValue> {
    let parsed = key.lines()
        .filter(|line| !line.starts_with("-"))
        .fold(String::new(), |mut data, line| {
        data.push_str(&line);
        data
    });

    let key_bytes = base64::decode(parsed).unwrap();

    let rsa_public = RSAPublicKey::from_pkcs1(&key_bytes).unwrap();

    let encrypted = rsa_public.encrypt(&mut OsRng, PaddingScheme::new_pkcs1v15_encrypt(), text.as_bytes()).unwrap();

    let encrypted_string = base64::encode(&encrypted);

    Ok(encrypted_string)
}
