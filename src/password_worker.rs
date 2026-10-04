use crate::password_finder::Strategy;
use crate::password_gen::password_generator_iter;
use crate::password_reader::password_dictionary_reader_iter;
use crate::zip_utils::AesInfo;
use either::Either;
use hmac::Hmac;
use indicatif::ProgressBar;
use sha1::Sha1;
use std::io::{self, BufReader, Cursor, Read, Seek};
use std::path::Path;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::SyncSender;
use std::thread::JoinHandle;
use std::{fs, thread};
use zip::ZipArchive;

fn verify_password<R: Read + Seek>(
    archive: &mut ZipArchive<R>,
    file_number: usize,
    password: &[u8],
) -> bool {
    // A wrong password can pass the encryption header check and then fail
    // while the decompressor is being constructed, with errors other than
    // InvalidPassword. Reject that candidate just like a read failure.
    let Ok(mut zip) = archive.by_index_decrypt(file_number, password) else {
        return false;
    };
    if zip.enclosed_name().is_none() {
        return false;
    }

    let expected_size = zip.size();
    // Read through EOF for CRC/AES authentication without allocating the
    // uncompressed file size or retaining its contents in memory.
    io::copy(&mut zip, &mut io::sink()).is_ok_and(|read| read == expected_size)
}

pub fn filter_for_worker_index(
    passwords: impl Iterator<Item = String>,
    worker_count: usize,
    index: usize,
) -> impl Iterator<Item = String> {
    if worker_count > 1 {
        Either::Left(
            passwords
                .enumerate()
                .filter_map(move |(i, line)| (i % worker_count == index - 1).then_some(line)),
        )
    } else {
        Either::Right(passwords)
    }
}

#[allow(clippy::too_many_arguments)]
pub fn password_checker(
    index: usize,
    worker_count: usize,
    file_path: &Path,
    file_number: usize,
    aes_info: Option<AesInfo>,
    strategy: Strategy,
    send_password_found: SyncSender<String>,
    stop_signal: Arc<AtomicBool>,
    progress_bar: ProgressBar,
) -> JoinHandle<()> {
    let file_path = file_path.to_owned();
    thread::Builder::new()
        .name(format!("worker-{index}"))
        .spawn(move || {
            let batching_delta = worker_count as u64 * 500;
            let first_worker = index == 1;
            let progress_bar_delta = batching_delta * worker_count as u64;
            let passwords_iter = match strategy {
                Strategy::GenPasswords {
                    charset,
                    min_password_len,
                    max_password_len,
                    starting_password,
                } => {
                    // password generator logs its progress, make sure only the first one does
                    let pb = if first_worker {
                        progress_bar.clone()
                    } else {
                        ProgressBar::hidden()
                    };
                    Either::Left(password_generator_iter(
                        charset,
                        min_password_len,
                        max_password_len,
                        starting_password,
                        pb,
                    ))
                }
                Strategy::PasswordFile(dictionary_path) => {
                    Either::Right(password_dictionary_reader_iter(dictionary_path))
                }
            };
            // filter passwords by worker index
            let passwords_iter = passwords_iter
                .map_left(|iter| filter_for_worker_index(iter, worker_count, index))
                .map_right(|iter| filter_for_worker_index(iter, worker_count, index));

            // AES info bindings
            let mut derived_key_len = 0;
            let mut derived_key: Vec<u8> = Vec::new();
            let mut salt: Vec<u8> = Vec::new();
            let mut verification_value: [u8; 2] = [0; 2];

            // setup file reader depending on the encryption method
            let reader = if let Some(aes_info) = aes_info {
                salt = aes_info.salt;
                verification_value = aes_info.verification_value;
                derived_key_len = aes_info.derived_key_length;
                derived_key = vec![0; derived_key_len];
                let file = fs::File::open(file_path).expect("File should exist");
                // in case of AES we do not need to access the archive often, a buffer reader is enough
                Either::Left(BufReader::new(file))
            } else {
                let zip_file = fs::read(file_path).expect("File should exist");
                // in case of ZipCrypto, we load the file in memory as it will be accessed on each password
                Either::Right(Cursor::new(zip_file))
            };

            // zip archive
            let mut archive = ZipArchive::new(reader).expect("Archive validated before-hand");

            // processing loop
            let mut processed_delta: u64 = 0;
            for password in passwords_iter {
                let password_bytes = password.as_bytes();
                let mut potential_match = true;
                // process AES KEY
                if derived_key_len != 0 {
                    // use PBKDF2 with HMAC-Sha1 to derive the key
                    pbkdf2::pbkdf2::<Hmac<Sha1>>(password_bytes, &salt, 1000, &mut derived_key)
                        .expect("PBKDF2 should not fail");
                    let pwd_verify = &derived_key[derived_key_len - 2..];
                    // the last 2 bytes should equal the password verification value
                    potential_match = verification_value == pwd_verify;
                }

                // ZipCrypto falls back directly here and will recompute its key for each password
                if potential_match {
                    // From the Rust doc:
                    // This function sometimes accepts wrong password. This is because the ZIP spec only allows us to check for a 1/256 chance that the password is correct.
                    // There are many passwords out there that will also pass the validity checks we are able to perform.
                    // This is a weakness of the ZipCrypto algorithm, due to its fairly primitive approach to cryptography.
                    if verify_password(&mut archive, file_number, password_bytes) {
                        // Send password and continue processing while waiting for signal
                        send_password_found
                            .send(password.clone())
                            .expect("Send found password should not fail");
                    }
                }
                processed_delta += 1;
                // do not check internal flags too often
                if processed_delta == batching_delta {
                    // only the first worker should update the progress bar to avoid contention
                    if first_worker {
                        progress_bar.inc(progress_bar_delta);
                    }
                    // check if we should stop
                    if stop_signal.load(Ordering::Relaxed) {
                        if first_worker {
                            progress_bar.println(format!("Last password processed:{password}"));
                        }
                        break;
                    }
                    processed_delta = 0;
                }
            }
        })
        .unwrap()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::{SeekFrom, Write};
    use std::path::PathBuf;
    use zip::unstable::write::FileOptionsExt;
    use zip::write::SimpleFileOptions;

    #[test]
    fn decryption_io_error_rejects_candidate_without_panicking() {
        struct FailingReader {
            inner: Cursor<Vec<u8>>,
            fail: Arc<AtomicBool>,
        }
        impl Read for FailingReader {
            fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
                if self.fail.load(Ordering::Relaxed) {
                    Err(io::Error::new(io::ErrorKind::InvalidData, "decoder error"))
                } else {
                    self.inner.read(buf)
                }
            }
        }
        impl Seek for FailingReader {
            fn seek(&mut self, pos: SeekFrom) -> io::Result<u64> {
                self.inner.seek(pos)
            }
        }

        let fail = Arc::new(AtomicBool::new(false));
        let reader = FailingReader {
            inner: Cursor::new(fs::read("test-files/2.test.txt.zip").unwrap()),
            fail: fail.clone(),
        };
        let mut archive = ZipArchive::new(reader).unwrap();
        fail.store(true, Ordering::Relaxed);
        assert!(!verify_password(&mut archive, 0, b"wrong"));
        fail.store(false, Ordering::Relaxed);
        assert!(verify_password(&mut archive, 0, b"ab"));
    }

    #[test]
    fn verify_large_encrypted_file_by_streaming() {
        let mut writer = zip::ZipWriter::new(Cursor::new(Vec::new()));
        let options = SimpleFileOptions::default()
            .compression_method(zip::CompressionMethod::Deflated)
            .with_deprecated_encryption(b"password")
            .unwrap();
        writer.start_file("large.txt", options).unwrap();
        let block = [b'a'; 8192];
        for _ in 0..2048 {
            writer.write_all(&block).unwrap();
        }
        let data = writer.finish().unwrap().into_inner();
        let mut archive = ZipArchive::new(Cursor::new(&data)).unwrap();
        assert!(!verify_password(&mut archive, 0, b"wrong"));
        assert!(verify_password(&mut archive, 0, b"password"));

        // A huge advertised size must not drive an allocation or bypass the
        // length check, even when the password and CRC are correct.
        let mut inflated_size = data;
        let central = inflated_size
            .windows(4)
            .position(|bytes| bytes == b"PK\x01\x02")
            .unwrap();
        inflated_size[central + 24..central + 28].copy_from_slice(&(u32::MAX - 1).to_le_bytes());
        let mut archive = ZipArchive::new(Cursor::new(inflated_size)).unwrap();
        assert!(!verify_password(&mut archive, 0, b"password"));
    }

    #[test]
    fn streaming_verification_checks_crc_at_eof() {
        let mut writer = zip::ZipWriter::new(Cursor::new(Vec::new()));
        let options = SimpleFileOptions::default()
            .with_deprecated_encryption(b"ab")
            .unwrap();
        writer.start_file("test.txt", options).unwrap();
        writer.write_all(b"contents").unwrap();
        let mut data = writer.finish().unwrap().into_inner();
        let central = data
            .windows(4)
            .position(|bytes| bytes == b"PK\x01\x02")
            .unwrap();
        // Preserve the high CRC byte used by ZipCrypto's password check.
        data[central + 16] ^= 1;
        let mut archive = ZipArchive::new(Cursor::new(data)).unwrap();
        assert!(archive.by_index_decrypt(0, b"ab").is_ok());
        assert!(!verify_password(&mut archive, 0, b"ab"));
    }

    #[test]
    fn streaming_verification_checks_aes_authentication() {
        let mut writer = zip::ZipWriter::new(Cursor::new(Vec::new()));
        let options = SimpleFileOptions::default().with_aes_encryption(zip::AesMode::Aes256, "ab");
        writer.start_file("test.txt", options).unwrap();
        writer.write_all(b"contents").unwrap();
        let mut data = writer.finish().unwrap().into_inner();
        let mut archive = ZipArchive::new(Cursor::new(&data)).unwrap();
        assert!(verify_password(&mut archive, 0, b"ab"));
        let zip = archive.by_index_decrypt(0, b"ab").unwrap();
        let authentication_end = (zip.data_start().unwrap() + zip.compressed_size()) as usize;
        drop(zip);
        drop(archive);
        data[authentication_end - 1] ^= 1;
        let mut archive = ZipArchive::new(Cursor::new(data)).unwrap();
        assert!(archive.by_index_decrypt(0, b"ab").is_ok());
        assert!(!verify_password(&mut archive, 0, b"ab"));
    }

    #[test]
    fn filter_passwords_one_worker() {
        let iter = password_dictionary_reader_iter(PathBuf::from(
            "test-files/generated-passwords-lowercase.txt",
        ));
        let mut filtered = filter_for_worker_index(iter, 1, 1);
        assert_eq!(filtered.next(), Some("a".into()));
        assert_eq!(filtered.next(), Some("b".into()));
        assert_eq!(filtered.next(), Some("c".into()));
        assert_eq!(filtered.next(), Some("d".into()));
        assert_eq!(filtered.next(), Some("e".into()));
        assert_eq!(filtered.next(), Some("f".into()));
        assert_eq!(filtered.next(), Some("g".into()));
        assert_eq!(filtered.next(), Some("h".into()));
        assert_eq!(filtered.next(), Some("i".into()));
        assert_eq!(filtered.next(), Some("j".into()));
        assert_eq!(filtered.next(), Some("k".into()));
        assert_eq!(filtered.next(), Some("l".into()));
    }

    #[test]
    fn filter_passwords_two_workers_index_one() {
        let iter = password_dictionary_reader_iter(PathBuf::from(
            "test-files/generated-passwords-lowercase.txt",
        ));
        let mut filtered = filter_for_worker_index(iter, 2, 1);
        assert_eq!(filtered.next(), Some("a".into()));
        //assert_eq!(filtered.next(), Some("b".into()));
        assert_eq!(filtered.next(), Some("c".into()));
        //assert_eq!(filtered.next(), Some("d".into()));
        assert_eq!(filtered.next(), Some("e".into()));
        //assert_eq!(filtered.next(), Some("f".into()));
        assert_eq!(filtered.next(), Some("g".into()));
        //assert_eq!(filtered.next(), Some("h".into()));
        assert_eq!(filtered.next(), Some("i".into()));
        //assert_eq!(filtered.next(), Some("j".into()));
        assert_eq!(filtered.next(), Some("k".into()));
        //assert_eq!(filtered.next(), Some("l".into()));
    }

    #[test]
    fn filter_passwords_two_workers_index_two() {
        let iter = password_dictionary_reader_iter(PathBuf::from(
            "test-files/generated-passwords-lowercase.txt",
        ));
        let mut filtered = filter_for_worker_index(iter, 2, 2);
        //assert_eq!(filtered.next(), Some("a".into()));
        assert_eq!(filtered.next(), Some("b".into()));
        //assert_eq!(filtered.next(), Some("c".into()));
        assert_eq!(filtered.next(), Some("d".into()));
        //assert_eq!(filtered.next(), Some("e".into()));
        assert_eq!(filtered.next(), Some("f".into()));
        //assert_eq!(filtered.next(), Some("g".into()));
        assert_eq!(filtered.next(), Some("h".into()));
        //assert_eq!(filtered.next(), Some("i".into()));
        assert_eq!(filtered.next(), Some("j".into()));
        //assert_eq!(filtered.next(), Some("k".into()));
        assert_eq!(filtered.next(), Some("l".into()));
    }

    #[test]
    fn filter_passwords_three_workers_index_one() {
        let iter = password_dictionary_reader_iter(PathBuf::from(
            "test-files/generated-passwords-lowercase.txt",
        ));
        let mut filtered = filter_for_worker_index(iter, 3, 1);
        assert_eq!(filtered.next(), Some("a".into()));
        //assert_eq!(filtered.next(), Some("b".into()));
        //assert_eq!(filtered.next(), Some("c".into()));
        assert_eq!(filtered.next(), Some("d".into()));
        //assert_eq!(filtered.next(), Some("e".into()));
        //assert_eq!(filtered.next(), Some("f".into()));
        assert_eq!(filtered.next(), Some("g".into()));
        //assert_eq!(filtered.next(), Some("h".into()));
        //assert_eq!(filtered.next(), Some("i".into()));
        assert_eq!(filtered.next(), Some("j".into()));
        //assert_eq!(filtered.next(), Some("k".into()));
        //assert_eq!(filtered.next(), Some("l".into()));
    }
}
