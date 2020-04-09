#[allow(warnings)]
#[no_mangle]
extern "C" fn _oasis_deploy() -> u8 {
    use oasis_std::{reexports::serde::Deserialize, Service as _};
    #[derive(Deserialize)]
    #[allow(non_camel_case_types)]
    struct CtorPayload();
    let ctx = oasis_std::Context::default();
    let mut service = <PortexPkg>::new(&ctx);
    <PortexPkg>::sunder(service);
    return 0;
}
