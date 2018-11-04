use openssl::{
    ec::*,
    hash::MessageDigest,
    pkey::{Public, Private, PKey},
    rand::rand_bytes,
    sign::{Signer, Verifier},
    nid::Nid,
    memcmp,
};

#[derive(Clone)]
pub struct PubKey {
    public_key: EcKey<Public>,
}

impl PubKey {
    fn pkey(&self) -> Result<PKey<Public>, String> {
        PKey::from_ec_key(self.public_key.clone()).map_err(|e| e.to_string())
    }

    pub fn from_der(key: &[u8]) -> Result<PubKey, String> {
        let pkey = PKey::public_key_from_der(key).map_err(|e| e.to_string())?;
        Ok(PubKey {
            public_key: pkey.ec_key().map_err(|e| e.to_string())?,
        })
    }

    pub fn to_der(&self) -> Result<Vec<u8>, String> {
        self.pkey()?.public_key_to_der().map_err(|e| e.to_string())
    }

    pub fn verify(&self, data: &[u8], signature: &[u8]) -> bool {
        let pkey = match self.pkey() {
            Ok(p) => p,
            Err(_) => return false,
        };

        let mut verifier = match Verifier::new(MessageDigest::sha256(), &pkey) {
            Ok(v) => v,
            Err(_) => return false,
        };

        match verifier.update(data) {
            Ok(_) => (),
            Err(_) => return false,
        };

        match verifier.verify(signature) {
            Ok(b) => b,
            Err(_) => false,
        }
    }
}

#[derive(Clone)]
pub struct PrivKey {
    pub public_key: PubKey,
    private_key: EcKey<Private>,
}

impl PrivKey {
    fn pkey(&self) -> Result<PKey<Private>, String> {
        PKey::from_ec_key(self.private_key.clone()).map_err(|e| e.to_string())
    }

    pub fn generate() -> Result<PrivKey, String> {
        let mut group = EcGroup::from_curve_name(Nid::X9_62_PRIME256V1).map_err(|e| e.to_string())?;
        group.set_asn1_flag(Asn1Flag::NAMED_CURVE);
        let key = EcKey::generate(&group).map_err(|e| e.to_string())?;
        let pkey = PKey::from_ec_key(key.clone()).map_err(|e| e.to_string())?;
        PrivKey::from_der(&pkey.private_key_to_der().map_err(|e| e.to_string())?)
    }

    pub fn from_der(key: &[u8]) -> Result<PrivKey, String> {
        let pkey = PKey::private_key_from_der(key).map_err(|e| e.to_string())?;
        Ok(PrivKey {
            public_key: PubKey::from_der(&pkey.public_key_to_der().map_err(|e| e.to_string())?)?,
            private_key: pkey.ec_key().map_err(|e| e.to_string())?,
        })
    }

    pub fn to_der(&self) -> Result<Vec<u8>, String> {
        self.pkey()?.private_key_to_der().map_err(|e| e.to_string())
    }

    pub fn sign(&self, bytes: &[u8]) -> Result<Vec<u8>, String> {
        let pkey = self.pkey()?;
        let mut signer = Signer::new(MessageDigest::sha256(), &pkey).map_err(|e| e.to_string())?;
        signer.update(bytes).map_err(|e| e.to_string())?;
        signer.sign_to_vec().map_err(|e| e.to_string())
    }
}

pub struct SecretKey {
    secret_key: PKey<Private>,
    pub bytes: Vec<u8>,
}

impl SecretKey {
    pub fn from(bytes: &[u8]) -> Result<SecretKey, String> {
        Ok(SecretKey {
            secret_key: PKey::hmac(bytes).map_err(|e| e.to_string())?,
            bytes: bytes.to_vec(),
        })
    }

    pub fn sign(&self, bytes: &[u8]) -> Result<Vec<u8>, String> {
        let mut signer = Signer::new(MessageDigest::sha256(), &self.secret_key).map_err(|e| e.to_string())?;
        signer.update(bytes).map_err(|e| e.to_string())?;
        signer.sign_to_vec().map_err(|e| e.to_string())
    }

    pub fn verify(&self, data: &[u8], signature: &[u8]) -> bool {
        let hash = match self.sign(data) {
            Ok(h) => h,
            Err(_) => return false,
        };
        if hash.len() != signature.len() {
            return false;
        }
        memcmp::eq(&hash, &signature)
    }
}

pub fn random(length: usize) -> Result<Vec<u8>, String> {
    let mut buf = vec![0; length];
    rand_bytes(&mut buf).map_err(|e| e.to_string())?;
    Ok(buf)
}