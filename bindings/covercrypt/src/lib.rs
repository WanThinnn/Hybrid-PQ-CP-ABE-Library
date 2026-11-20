//! Native C ABI for the vendored CoverCrypt KEM. No cryptographic primitives are reimplemented.
use cosmian_cover_crypt::{traits::KemAc, AccessPolicy, Covercrypt, EncryptionHint,
    MasterPublicKey, MasterSecretKey, QualifiedAttribute, UserSecretKey, XEnc};
use cosmian_crypto_core::bytes_ser_de::Serializable;
use serde::Deserialize;
use std::{cell::RefCell, ffi::{c_char, CStr, CString}, panic::{catch_unwind, AssertUnwindSafe}, ptr, slice};
use zeroize::Zeroize;

const INVALID: i32 = -1;
const ERROR: i32 = -2;
const DENIED: i32 = -3;
type Result<T> = std::result::Result<T, (i32, String)>;
thread_local! { static LAST_ERROR: RefCell<CString> = RefCell::new(CString::new("").unwrap()); }

#[repr(C)]
pub struct Buffer { pub data: *mut u8, pub len: usize }

fn diagnostic(message: &str) {
    LAST_ERROR.with(|error| *error.borrow_mut() = CString::new(message.replace('\0', " ")).unwrap());
}
fn operation(task: impl FnOnce() -> Result<()>) -> i32 {
    diagnostic("");
    match catch_unwind(AssertUnwindSafe(task)) {
        Ok(Ok(())) => 0,
        Ok(Err((status, message))) => { diagnostic(&message); status }
        Err(_) => { diagnostic("CoverCrypt operation panicked"); -4 }
    }
}
fn failure(error: impl std::fmt::Display) -> (i32, String) { (ERROR, error.to_string()) }
unsafe fn bytes<'a>(data: *const u8, len: usize) -> Result<&'a [u8]> {
    if data.is_null() || len == 0 || len > isize::MAX as usize {
        return Err((INVALID, "invalid input buffer".into()));
    }
    Ok(slice::from_raw_parts(data, len))
}
unsafe fn text<'a>(data: *const c_char) -> Result<&'a str> {
    if data.is_null() { return Err((INVALID, "null text pointer".into())); }
    let value = CStr::from_ptr(data).to_str().map_err(|_| (INVALID, "text must be UTF-8 ASCII".into()))?;
    if !value.is_ascii() || value.is_empty() { return Err((INVALID, "text must be nonempty ASCII".into())); }
    Ok(value)
}
unsafe fn output(buffer: *mut Buffer) -> Result<()> {
    if buffer.is_null() || !(*buffer).data.is_null() || (*buffer).len != 0 {
        return Err((INVALID, "output must point to an empty cc_buffer".into()));
    }
    Ok(())
}
unsafe fn outputs(first: *mut Buffer, second: *mut Buffer) -> Result<()> {
    if first == second { return Err((INVALID, "output buffers must be distinct".into())); }
    output(first)?;
    output(second)
}
unsafe fn store(buffer: *mut Buffer, data: Vec<u8>) {
    let boxed = data.into_boxed_slice();
    (*buffer).len = boxed.len();
    (*buffer).data = Box::into_raw(boxed) as *mut u8;
}
fn serialize<T: Serializable>(value: &T) -> Result<Vec<u8>> {
    Ok(value.serialize().map_err(failure)?.to_vec())
}
fn policy(value: &str) -> Result<AccessPolicy> { AccessPolicy::parse(value).map_err(failure) }

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Configuration { dimensions: Vec<Dimension> }
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Dimension { name: String, attributes: Vec<String>, #[serde(default)] hierarchical: bool }

/// See covercrypt_ffi.h for pointer and ownership requirements.
#[no_mangle]
pub unsafe extern "C" fn cc_setup(config: *const c_char, mode: i32, msk_out: *mut Buffer, mpk_out: *mut Buffer) -> i32 {
    operation(|| {
        outputs(msk_out, mpk_out)?;
        let hint = match mode { 0 => EncryptionHint::Classic, 1 => EncryptionHint::PostQuantum,
            2 => EncryptionHint::Hybridized, _ => return Err((INVALID, "unknown encryption mode".into())) };
        let config: Configuration = serde_json::from_str(text(config)?).map_err(|e| (INVALID, e.to_string()))?;
        if config.dimensions.is_empty() { return Err((INVALID, "at least one dimension is required".into())); }
        let cc = Covercrypt::default();
        let (mut msk, _) = cc.setup().map_err(failure)?;
        for dimension in config.dimensions {
            if dimension.name.is_empty() || !dimension.name.is_ascii() || dimension.attributes.is_empty() {
                return Err((INVALID, "dimensions require ASCII names and attributes".into()));
            }
            if dimension.hierarchical {
                msk.access_structure.add_hierarchy(dimension.name.clone()).map_err(failure)?;
            } else { msk.access_structure.add_anarchy(dimension.name.clone()).map_err(failure)?; }
            let mut previous: Option<String> = None;
            for attribute in dimension.attributes {
                if attribute.is_empty() || !attribute.is_ascii() {
                    return Err((INVALID, "attribute must be nonempty ASCII".into()));
                }
                msk.access_structure.add_attribute(QualifiedAttribute::new(&dimension.name, &attribute),
                    hint, if dimension.hierarchical { previous.as_deref() } else { None }).map_err(failure)?;
                previous = Some(attribute);
            }
        }
        let mpk = cc.update_msk(&mut msk).map_err(failure)?;
        let msk_bytes = serialize(&msk)?;
        let mpk_bytes = serialize(&mpk)?;
        store(msk_out, msk_bytes);
        store(mpk_out, mpk_bytes);
        Ok(())
    })
}

#[no_mangle]
pub unsafe extern "C" fn cc_add_dimension(msk: *const u8, len: usize,
    config: *const c_char, mode: i32, updated_msk: *mut Buffer, updated_mpk: *mut Buffer) -> i32 {
    operation(|| {
        outputs(updated_msk, updated_mpk)?;
        let hint = match mode {
            0 => EncryptionHint::Classic,
            1 => EncryptionHint::PostQuantum,
            2 => EncryptionHint::Hybridized,
            _ => return Err((INVALID, "unknown encryption mode".into())),
        };
        let dimension: Dimension = serde_json::from_str(text(config)?)
            .map_err(|error| (INVALID, error.to_string()))?;
        if dimension.name.is_empty() || !dimension.name.is_ascii() || dimension.attributes.is_empty() {
            return Err((INVALID, "dimension requires an ASCII name and attributes".into()));
        }
        let mut msk = MasterSecretKey::deserialize(bytes(msk, len)?).map_err(failure)?;
        if dimension.hierarchical {
            msk.access_structure.add_hierarchy(dimension.name.clone()).map_err(failure)?;
        } else {
            msk.access_structure.add_anarchy(dimension.name.clone()).map_err(failure)?;
        }
        let mut previous: Option<String> = None;
        for attribute in dimension.attributes {
            if attribute.is_empty() || !attribute.is_ascii() {
                return Err((INVALID, "attribute must be nonempty ASCII".into()));
            }
            msk.access_structure.add_attribute(QualifiedAttribute::new(&dimension.name, &attribute),
                hint, if dimension.hierarchical { previous.as_deref() } else { None }).map_err(failure)?;
            previous = Some(attribute);
        }
        // update_msk retains existing right secrets and creates only missing
        // ones. setup/rekey would have different authority/rotation semantics.
        let mpk = Covercrypt::default().update_msk(&mut msk).map_err(failure)?;
        let secret = serialize(&msk)?;
        let public = serialize(&mpk)?;
        store(updated_msk, secret);
        store(updated_mpk, public);
        Ok(())
    })
}

#[no_mangle]
pub unsafe extern "C" fn cc_add_attribute(msk: *const u8, len: usize,
    dimension: *const c_char, attribute: *const c_char, mode: i32, after: *const c_char,
    updated_msk: *mut Buffer, updated_mpk: *mut Buffer) -> i32 {
    operation(|| {
        outputs(updated_msk, updated_mpk)?;
        let hint = match mode {
            0 => EncryptionHint::Classic,
            1 => EncryptionHint::PostQuantum,
            2 => EncryptionHint::Hybridized,
            _ => return Err((INVALID, "unknown encryption mode".into())),
        };
        let dimension = text(dimension)?;
        let attribute = text(attribute)?;
        let after = if after.is_null() { None } else { Some(text(after)?) };
        let mut msk = MasterSecretKey::deserialize(bytes(msk, len)?).map_err(failure)?;
        msk.access_structure
            .add_attribute(QualifiedAttribute::new(dimension, attribute), hint, after)
            .map_err(failure)?;
        let mpk = Covercrypt::default().update_msk(&mut msk).map_err(failure)?;
        store(updated_msk, serialize(&msk)?);
        store(updated_mpk, serialize(&mpk)?);
        Ok(())
    })
}

#[no_mangle]
pub unsafe extern "C" fn cc_genkey(msk: *const u8, len: usize, ap: *const c_char,
    updated: *mut Buffer, usk_out: *mut Buffer) -> i32 {
    operation(|| {
        outputs(updated, usk_out)?;
        let mut msk = MasterSecretKey::deserialize(bytes(msk, len)?).map_err(failure)?;
        let usk = Covercrypt::default().generate_user_secret_key_restricted(&mut msk, &policy(text(ap)?)?).map_err(failure)?;
        let msk_bytes = serialize(&msk)?;
        let usk_bytes = serialize(&usk)?;
        store(updated, msk_bytes);
        store(usk_out, usk_bytes);
        Ok(())
    })
}

/// Stateless Buffer API: register the user in a temporary authority as usual,
/// but do not serialize the updated master key that the caller will discard.
/// File-based callers must keep using cc_genkey and persist its updated MSK.
#[no_mangle]
pub unsafe extern "C" fn cc_genkey_ephemeral(msk: *const u8, len: usize, ap: *const c_char,
    usk_out: *mut Buffer) -> i32 {
    operation(|| {
        output(usk_out)?;
        let mut msk = MasterSecretKey::deserialize(bytes(msk, len)?).map_err(failure)?;
        let usk = Covercrypt::default().generate_user_secret_key_restricted(&mut msk, &policy(text(ap)?)?).map_err(failure)?;
        store(usk_out, serialize(&usk)?);
        Ok(())
    })
}

#[no_mangle]
pub unsafe extern "C" fn cc_encaps(mpk: *const u8, len: usize, ap: *const c_char,
    secret_out: *mut Buffer, enc_out: *mut Buffer) -> i32 {
    operation(|| {
        outputs(secret_out, enc_out)?;
        let mpk = MasterPublicKey::deserialize(bytes(mpk, len)?).map_err(failure)?;
        let (secret, enc) = Covercrypt::default().encaps(&mpk, &policy(text(ap)?)?).map_err(failure)?;
        let encoded = serialize(&enc)?;
        store(secret_out, secret.to_vec());
        store(enc_out, encoded);
        Ok(())
    })
}

#[no_mangle]
pub unsafe extern "C" fn cc_decaps(usk: *const u8, usk_len: usize, enc: *const u8, enc_len: usize,
    secret_out: *mut Buffer) -> i32 {
    operation(|| {
        output(secret_out)?;
        let usk = UserSecretKey::deserialize(bytes(usk, usk_len)?).map_err(failure)?;
        let enc = XEnc::deserialize(bytes(enc, enc_len)?).map_err(failure)?;
        let secret = Covercrypt::default().decaps(&usk, &enc).map_err(failure)?
            .ok_or_else(|| (DENIED, "key does not authorize this encapsulation".into()))?;
        store(secret_out, secret.to_vec());
        Ok(())
    })
}

#[no_mangle]
pub unsafe extern "C" fn cc_buffer_free(buffer: *mut Buffer) {
    if !buffer.is_null() {
        if !(*buffer).data.is_null() {
            let mut data = Box::from_raw(ptr::slice_from_raw_parts_mut((*buffer).data, (*buffer).len));
            data.zeroize();
        }
        (*buffer).data = ptr::null_mut();
        (*buffer).len = 0;
    }
}
#[no_mangle]
pub extern "C" fn cc_last_error() -> *const c_char {
    LAST_ERROR.with(|error| error.borrow().as_ptr())
}
