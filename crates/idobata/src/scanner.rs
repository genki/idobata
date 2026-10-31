use crate::{
    error::{Result, SCANNER},
    types::{Draft, Report},
    util,
};
use serde_json::json;
use wasmi::{Config, Engine, Linker, Module, Store, StoreLimits, StoreLimitsBuilder};
const WASM: &[u8] = include_bytes!("../assets/scanner.wasm");
pub struct Scanner {
    engine: Engine,
    module: Module,
}
impl Scanner {
    pub fn new() -> Result<Self> {
        let mut config = Config::default();
        config.consume_fuel(true);
        let engine = Engine::new(&config);
        let module = Module::new(&engine, WASM).map_err(|_| SCANNER)?;
        if module.imports().next().is_some() {
            return Err(SCANNER);
        }
        Ok(Self { engine, module })
    }
    pub fn profile() -> serde_json::Value {
        json!({"id":idobata_scanner::PROFILE,"algorithm":"sliding-window-shannon-q20-v1","scale":1048576,"window_sizes_bytes":[16,32,64,128],"thresholds_q20":{"hex":[3407872,3774874,3879731,3984589],"base64":[3932160,4718592,5138022,5347738],"other":[4194304,4928307,5557453,6081741]},"log2_q20":idobata_scanner::LOGS.to_vec(),"short_generic_text_windows":"compact-ascii-only","max_input_bytes":8192,"max_decode_depth":3,"max_decoded_bytes":262144,"max_decode_candidates":128,"wasm_sha256":util::hash(WASM),"fuel":200_000_000,"memory_bytes":33_554_432})
    }
    pub fn policy_id() -> String {
        static ID: std::sync::OnceLock<String> = std::sync::OnceLock::new();
        ID.get_or_init(|| {
            util::hash(&util::canonical(&Self::profile()).expect("fixed public profile"))
        })
        .clone()
    }
    pub fn scan(&self, draft: &Draft, redact: bool) -> Result<Report> {
        let input = serde_json::to_vec(&idobata_scanner::Input {
            draft: draft.clone(),
            redact,
        })
        .map_err(|_| SCANNER)?;
        if input.len() > 65536 {
            return Err(SCANNER);
        }
        let limits = StoreLimitsBuilder::new()
            .memory_size(32 * 1024 * 1024)
            .instances(1)
            .memories(1)
            .tables(1)
            .table_elements(4096)
            .build();
        let mut store = Store::new(&self.engine, limits);
        store.limiter(|l: &mut StoreLimits| l);
        store.set_fuel(200_000_000).map_err(|_| SCANNER)?;
        let linker = Linker::<StoreLimits>::new(&self.engine);
        let instance = linker
            .instantiate_and_start(&mut store, &self.module)
            .map_err(|_| SCANNER)?;
        let allocate = instance
            .get_typed_func::<u32, u32>(&store, "allocate")
            .map_err(|_| SCANNER)?;
        let inspect = instance
            .get_typed_func::<(u32, u32), u64>(&store, "inspect")
            .map_err(|_| SCANNER)?;
        let memory = instance.get_memory(&store, "memory").ok_or(SCANNER)?;
        let ptr = allocate
            .call(&mut store, input.len() as u32)
            .map_err(|_| SCANNER)?;
        memory
            .write(&mut store, ptr as usize, &input)
            .map_err(|_| SCANNER)?;
        let out = inspect
            .call(&mut store, (ptr, input.len() as u32))
            .map_err(|_| SCANNER)?;
        let len = out as u32 as usize;
        let ptr = (out >> 32) as usize;
        if len > 65536 {
            return Err(SCANNER);
        }
        let mut bytes = vec![0u8; len];
        memory.read(&store, ptr, &mut bytes).map_err(|_| SCANNER)?;
        let report: Report = serde_json::from_slice(&bytes).map_err(|_| SCANNER)?;
        if report.profile != idobata_scanner::PROFILE || ![0, 20, 22, 30].contains(&report.code) {
            return Err(SCANNER);
        }
        Ok(report)
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn wasm_matches_native() {
        let scanner = Scanner::new().unwrap();
        for body in [
            "The work is ready.",
            "作業が完了しました。",
            "9aK7mP2xQ8vR4zT6nJ1bW5sL3cF0hD9u",
        ] {
            let d = Draft::plain(body.into());
            let wasm = scanner.scan(&d, false).unwrap();
            let native = idobata_scanner::scan(idobata_scanner::Input {
                draft: d,
                redact: false,
            });
            assert_eq!(
                serde_json::to_value(wasm).unwrap(),
                serde_json::to_value(native).unwrap()
            );
        }
    }
    #[test]
    fn module_has_no_host_imports() {
        assert!(Scanner::new().unwrap().module.imports().next().is_none());
    }
    #[test]
    fn wasm_large_plaintext() {
        let d = Draft::plain("The work is ready. ".repeat(400));
        assert_eq!(Scanner::new().unwrap().scan(&d, false).unwrap().code, 0);
    }
}
