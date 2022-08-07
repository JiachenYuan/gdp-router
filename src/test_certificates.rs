#[cfg(test)]
mod certificate_tests {

use anyhow::Error;
use crate::certificates::{CertLoc, Certificate};
use crate::structs::{GdpName, GdpMeta};

    pub fn new_certificate() -> Result<Certificate, Error> {
        let origin: GdpName = [123; 32];
        let dest = GdpMeta{ pub_key: [111; 32] };
        let private_key = [2; 32];
        let cert = Certificate::new(
                origin, 
                CertLoc::GdpName(dest.hash()),
                private_key,
                false
            );
       cert 
    }

    #[test]
    fn test_owner() {
        let cert_result = new_certificate(); 
        assert!(cert_result.is_ok());
        let cert = cert_result.unwrap();
        assert_eq!(cert.owner(), [123; 32]);
    }
}
