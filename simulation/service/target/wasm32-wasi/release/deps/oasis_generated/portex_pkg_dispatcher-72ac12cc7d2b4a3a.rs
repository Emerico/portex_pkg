#[allow(warnings)]
fn _oasis_dispatcher() {
    use oasis_std::{reexports::serde::Deserialize, Service as _};
    #[derive(Deserialize)]
    #[serde(tag = "method", content = "payload")]
    enum RpcPayload {
        extract_key_simulation((String,)),
    }
    let ctx = oasis_std::Context::default();
    let mut service = <PortexPkg>::coalesce();
    let input = oasis_std::backend::input();
    let payload: RpcPayload = oasis_std::reexports::serde_cbor::from_slice(&input).unwrap();
    let output: std::result::Result<Vec<u8>, Vec<u8>> = match payload {
        RpcPayload::extract_key_simulation((id,)) => {
            match service.extract_key_simulation(&ctx, id) {
                Ok(output) => Ok(oasis_std::reexports::serde_cbor::to_vec(&output).unwrap()),
                Err(err) => Err(oasis_std::reexports::serde_cbor::to_vec(&err).unwrap()),
            }
        }
    };
    match output {
        Ok(output) => oasis_std::backend::ret(&output),
        Err(err_output) => oasis_std::backend::err(&err_output),
    }
}
