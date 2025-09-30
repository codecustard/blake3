# BLAKE3 Motoko Library

A pure Motoko implementation of the BLAKE3 cryptographic hash function for the Internet Computer Platform (ICP). This library provides fast, secure hashing for blockchain integration and other ICP applications.

## Features

- ✅ **Official BLAKE3 Algorithm**: Based on the official C implementation from the BLAKE3 team
- ✅ **Complete Test Coverage**: All 15 tests pass, including official test vectors
- ✅ **Pure Motoko**: No external dependencies, runs natively on ICP
- ✅ **Multiple Hash Modes**: Regular hashing, keyed hashing, and key derivation
- ✅ **Streaming API**: Support for incremental hashing of large inputs
- ✅ **Verified Correctness**: Produces identical outputs to reference implementations

## Quick Start

### Installation

Add to your `mops.toml`:

```toml
[dependencies]
blake3 = "0.1.2"
```

### Basic Usage

```motoko
import Blake3 "mo:blake3";
import Text "mo:base/Text";

// Simple hashing
let data = Text.encodeUtf8("hello world");
let hash = Blake3.digest(data);

// With configuration
let hash2 = Blake3.hash(data, ?{
    key = null;
    context = null;
    derive_key = false;
});
```

### Keyed Hashing

```motoko
import Blake3 "mo:blake3";
import Text "mo:base/Text";

let key = Text.encodeUtf8("my-secret-key-32-bytes-long!!!");
let message = Text.encodeUtf8("authenticated message");
let keyed_hash = Blake3.keyed_hash(key, message);
```

### Key Derivation

```motoko
import Blake3 "mo:blake3";
import Text "mo:base/Text";

let context = "my-app-v1.0-key-derivation";
let key_material = Text.encodeUtf8("source-key-material");
let derived_key = Blake3.derive_key(context, key_material);
```

### Streaming API

```motoko
import Blake3 "mo:blake3";
import Text "mo:base/Text";

let hasher = Blake3.init(null);
Blake3.update(hasher, Text.encodeUtf8("part 1"));
Blake3.update(hasher, Text.encodeUtf8("part 2"));
Blake3.update(hasher, Text.encodeUtf8("part 3"));
let final_hash = Blake3.finalize(hasher);
```

## API Reference

### Types

```motoko
public type Blake3Config = {
    key: ?Blob;
    context: ?Text;
    derive_key: Bool;
};

public type Blake3Hasher = {
    // Internal state for streaming hashing
};
```

### Functions

#### `digest(data: Blob) : Blob`
Simple one-shot hashing with default parameters.

#### `hash(data: Blob, config: ?Blake3Config) : Blob`
Configurable one-shot hashing.

#### `keyed_hash(key: Blob, data: Blob) : Blob`
Keyed hashing for authentication. Key must be exactly 32 bytes.

#### `derive_key(context: Text, key_material: Blob) : Blob`
Key derivation function for generating keys from master material.

#### `init(config: ?Blake3Config) : Blake3Hasher`
Initialize a hasher for streaming API.

#### `update(hasher: Blake3Hasher, input: Blob)`
Add data to the hasher (can be called multiple times).

#### `finalize(hasher: Blake3Hasher) : Blob`
Finalize and return the hash output.

## Testing

Run the comprehensive test suite:

```bash
mops test
```

Tests include:
- Official BLAKE3 test vectors
- Empty input edge cases
- Large input handling
- Streaming vs one-shot consistency
- Keyed hashing verification
- Key derivation validation

## Implementation Details

- **Algorithm**: BLAKE3 with 32-byte output
- **Block Size**: 64 bytes
- **Rounds**: 7 compression rounds
- **Word Size**: 32-bit little-endian
- **Based On**: Official BLAKE3 C implementation

## Use Cases

- **Blockchain Integration**: Address generation and transaction hashing
- **Content Addressing**: Fast hashing for content-addressable storage
- **Authentication**: Keyed hashing for message authentication
- **Key Management**: Key derivation for hierarchical key systems
- **General Purpose**: Fast, secure hashing for any ICP application

## Performance

This pure Motoko implementation prioritizes correctness and compatibility over raw speed. For high-performance applications requiring millions of hashes per second, consider the official WebAssembly implementations.

## Security

BLAKE3 is a cryptographically secure hash function designed to be:
- **Fast**: Faster than MD5, SHA-1, SHA-2, and SHA-3
- **Secure**: Resistant to length extension attacks
- **Simple**: Fewer parameters and edge cases than other hash functions
- **Parallel**: Supports parallel computation (though not utilized in this implementation)

## License

MIT License - see LICENSE file for details.

## Contributing

1. Fork the repository
2. Create a feature branch
3. Add tests for new functionality
4. Ensure all tests pass with `mops test`
5. Submit a pull request

## Links

- [BLAKE3 Official Repository](https://github.com/BLAKE3-team/BLAKE3)
- [BLAKE3 Paper](https://github.com/BLAKE3-team/BLAKE3-specs)
- [Motoko Documentation](https://internetcomputer.org/docs/current/motoko/main/motoko)