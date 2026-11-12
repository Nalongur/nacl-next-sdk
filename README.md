# NaCL Next SDK

Rust SDK for local instance management, Java detection, identity providers, launch preparation, and generic transfer and installation plans. The optional `microsoft` feature enables Microsoft account support.

## Install

```toml
[dependencies]
nacl-next-sdk = { git = "https://github.com/Nalongur/nacl-next-sdk.git", tag = "0.1.0-preview.1" }
```

## Example

```rust
use nacl_next_sdk::capability::CapabilityRegistry;

fn main() {
    for capability in CapabilityRegistry::builtin().list() {
        println!("{}.{}", capability.namespace, capability.name);
    }
}
```

See `examples/` for complete local profile and custom identity examples, and `nacl-next-sdk/src/lib.rs` for the API. The SDK is licensed under [MIT](LICENSE); third-party notices and license texts are in [third-party/](third-party/).
