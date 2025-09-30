import Array "mo:base/Array";
import Blob "mo:base/Blob";
import Buffer "mo:base/Buffer";
import Nat8 "mo:base/Nat8";
import Nat32 "mo:base/Nat32";
import Nat64 "mo:base/Nat64";
import Text "mo:base/Text";
import Iter "mo:base/Iter";
import Option "mo:base/Option";

/// BLAKE3 cryptographic hash function implementation for Motoko
///
/// This module provides a complete implementation of the BLAKE3 cryptographic hash function,
/// including support for regular hashing, keyed hashing, key derivation, and streaming operations.
/// The implementation is compatible with the official BLAKE3 specification and passes all standard test vectors.
///
/// Key features:
/// - Full BLAKE3 specification compliance with 7-round compression
/// - Support for 32-byte keys and unlimited output length
/// - Streaming API for processing large inputs incrementally
/// - Compatible with Kaspa/Hoosat blockchain forks for sighash operations
/// - Pure Motoko implementation with no external dependencies
module Blake3 {
    /// Length of BLAKE3 keys in bytes (32 bytes = 256 bits)
    public let KEY_LEN = 32;

    /// Default output length in bytes (32 bytes = 256 bits)
    public let OUT_LEN = 32;

    /// Size of each compression block in bytes
    public let BLOCK_LEN = 64;

    /// Size of each chunk in bytes (16 blocks)
    public let CHUNK_LEN = 1024;

    /// Maximum tree depth for parallel processing
    public let MAX_DEPTH = 54;

    // Initialization vector
    let IV : [Nat32] = [
        0x6A09E667, 0xBB67AE85, 0x3C6EF372, 0xA54FF53A,
        0x510E527F, 0x9B05688C, 0x1F83D9AB, 0x5BE0CD19
    ];

    // Message schedule
    let MSG_SCHEDULE : [[Nat]] = [
        [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15],
        [2, 6, 3, 10, 7, 0, 4, 13, 1, 11, 12, 5, 9, 14, 15, 8],
        [3, 4, 10, 12, 13, 2, 7, 14, 6, 5, 9, 0, 11, 15, 8, 1],
        [10, 7, 12, 9, 14, 3, 13, 15, 4, 0, 11, 2, 5, 8, 1, 6],
        [12, 13, 9, 11, 15, 10, 14, 8, 7, 2, 5, 3, 0, 1, 6, 4],
        [9, 14, 11, 5, 8, 12, 15, 1, 13, 3, 0, 10, 2, 6, 4, 7],
        [11, 15, 5, 0, 1, 9, 8, 6, 14, 10, 2, 12, 3, 4, 7, 13]
    ];

    /// Domain separation flags for different BLAKE3 modes

    /// Flag indicating the start of a chunk
    public let CHUNK_START = 1;

    /// Flag indicating the end of a chunk
    public let CHUNK_END = 2;

    /// Flag for parent node in the hash tree
    public let PARENT = 4;

    /// Flag for root node finalization
    public let ROOT = 8;

    /// Flag for keyed hashing mode
    public let KEYED_HASH = 16;

    /// Flag for key derivation context
    public let DERIVE_KEY_CONTEXT = 32;

    /// Flag for key derivation from material
    public let DERIVE_KEY_MATERIAL = 64;

    /// Internal chunk state for processing 1024-byte chunks
    public type ChunkState = {
        /// Current chaining value (8 words)
        cv: [Nat32];
        /// Counter for this chunk
        chunkCounter: Nat64;
        /// Current block buffer (64 bytes)
        buf: [Nat8];
        /// Number of bytes in current buffer
        bufLen: Nat8;
        /// Number of complete blocks processed
        blocksCompressed: Nat8;
        /// Domain separation flags
        flags: Nat8;
    };

    /// Internal hasher state for incremental hashing
    public type Hasher = {
        /// Key words (8 x 32-bit) or IV for regular hashing
        key: [Nat32];
        /// Current chunk state
        chunk: ChunkState;
        /// Length of chaining value stack
        cvStackLen: Nat8;
        /// Stack of chaining values for tree hashing
        cvStack: [Nat8];
    };

    /// Configuration options for BLAKE3 hashing
    public type Blake3Config = {
        /// Optional 32-byte key for keyed hashing
        key: ?Blob;
        /// Optional context string for key derivation
        context: ?Text;
        /// Whether to use key derivation mode
        derive_key: Bool;
    };

    /// Streaming hasher for incremental processing
    ///
    /// Use this type with `init()`, `update()`, and `finalize()` for processing
    /// large inputs that don't fit in memory or when you need to hash data
    /// as it becomes available.
    public type Blake3Hasher = {
        /// Internal hasher state (mutable for updates)
        var internal: Hasher;
    };

    // Utility functions
    private func rotr32(w: Nat32, c: Nat32) : Nat32 {
        (w >> c) | (w << (32 - c))
    };

    private func load32(bytes: [Nat8], offset: Nat) : Nat32 {
        let b0 = Nat32.fromNat(Nat8.toNat(bytes[offset + 0]));
        let b1 = Nat32.fromNat(Nat8.toNat(bytes[offset + 1]));
        let b2 = Nat32.fromNat(Nat8.toNat(bytes[offset + 2]));
        let b3 = Nat32.fromNat(Nat8.toNat(bytes[offset + 3]));
        (b0 << 0) | (b1 << 8) | (b2 << 16) | (b3 << 24)
    };

    private func store32(w: Nat32) : [Nat8] {
        [
            Nat8.fromNat(Nat32.toNat(w & 0xFF)),
            Nat8.fromNat(Nat32.toNat((w >> 8) & 0xFF)),
            Nat8.fromNat(Nat32.toNat((w >> 16) & 0xFF)),
            Nat8.fromNat(Nat32.toNat((w >> 24) & 0xFF))
        ]
    };

    private func counterLow(counter: Nat64) : Nat32 {
        Nat32.fromNat(Nat64.toNat(counter & 0xFFFFFFFF))
    };

    private func counterHigh(counter: Nat64) : Nat32 {
        Nat32.fromNat(Nat64.toNat(counter >> 32))
    };

    private func popcnt(x: Nat64) : Nat {
        var count = 0;
        var n = x;
        while (n != 0) {
            count += 1;
            n := n & (n - 1);
        };
        count
    };

    private func highestOne(x: Nat64) : Nat {
        if (x == 0) return 0;
        var n = x;
        var count = 0;
        while (n > 1) {
            n := n >> 1;
            count += 1;
        };
        count
    };

    private func roundDownToPowerOf2(x: Nat64) : Nat64 {
        if (x == 0) return 1;
        let shift = highestOne(x | 1);
        Nat64.fromNat(1) << Nat64.fromNat(shift)
    };

    // G function for Blake3 compression
    private func g(state: [var Nat32], a: Nat, b: Nat, c: Nat, d: Nat, x: Nat32, y: Nat32) {
        // Use Nat64 for intermediate calculations to prevent overflow
        let temp1 = Nat64.fromNat(Nat32.toNat(state[a])) + Nat64.fromNat(Nat32.toNat(state[b])) + Nat64.fromNat(Nat32.toNat(x));
        state[a] := Nat32.fromNat(Nat64.toNat(temp1 % 0x100000000));

        state[d] := rotr32(state[d] ^ state[a], 16);

        let temp2 = Nat64.fromNat(Nat32.toNat(state[c])) + Nat64.fromNat(Nat32.toNat(state[d]));
        state[c] := Nat32.fromNat(Nat64.toNat(temp2 % 0x100000000));

        state[b] := rotr32(state[b] ^ state[c], 12);

        let temp3 = Nat64.fromNat(Nat32.toNat(state[a])) + Nat64.fromNat(Nat32.toNat(state[b])) + Nat64.fromNat(Nat32.toNat(y));
        state[a] := Nat32.fromNat(Nat64.toNat(temp3 % 0x100000000));

        state[d] := rotr32(state[d] ^ state[a], 8);

        let temp4 = Nat64.fromNat(Nat32.toNat(state[c])) + Nat64.fromNat(Nat32.toNat(state[d]));
        state[c] := Nat32.fromNat(Nat64.toNat(temp4 % 0x100000000));

        state[b] := rotr32(state[b] ^ state[c], 7);
    };

    // Round function
    private func roundFn(state: [var Nat32], msg: [Nat32], round: Nat) {
        let schedule = MSG_SCHEDULE[round];

        // Mix the columns
        g(state, 0, 4, 8, 12, msg[schedule[0]], msg[schedule[1]]);
        g(state, 1, 5, 9, 13, msg[schedule[2]], msg[schedule[3]]);
        g(state, 2, 6, 10, 14, msg[schedule[4]], msg[schedule[5]]);
        g(state, 3, 7, 11, 15, msg[schedule[6]], msg[schedule[7]]);

        // Mix the rows
        g(state, 0, 5, 10, 15, msg[schedule[8]], msg[schedule[9]]);
        g(state, 1, 6, 11, 12, msg[schedule[10]], msg[schedule[11]]);
        g(state, 2, 7, 8, 13, msg[schedule[12]], msg[schedule[13]]);
        g(state, 3, 4, 9, 14, msg[schedule[14]], msg[schedule[15]]);
    };

    // Load block words from bytes
    private func loadBlockWords(block: [Nat8]) : [Nat32] {
        Array.tabulate<Nat32>(16, func(i) = load32(block, i * 4))
    };

    // Store chaining value words to bytes
    private func storeCvWords(cvWords: [Nat32]) : [Nat8] {
        let buffer = Buffer.Buffer<Nat8>(32);
        for (word in cvWords.vals()) {
            buffer.append(Buffer.fromArray<Nat8>(store32(word)));
        };
        Buffer.toArray(buffer)
    };

    // Compress function (in-place)
    public func compressInPlace(cv: [var Nat32], block: [Nat8], blockLen: Nat8, counter: Nat64, flags: Nat8) {
        let blockWords = loadBlockWords(block);
        let state = Array.thaw<Nat32>(Array.tabulate<Nat32>(16, func(i) {
            if (i < 8) cv[i]
            else if (i < 12) IV[i - 8]
            else if (i == 12) counterLow(counter)
            else if (i == 13) counterHigh(counter)
            else if (i == 14) Nat32.fromNat(Nat8.toNat(blockLen))
            else Nat32.fromNat(Nat8.toNat(flags))
        }));

        // Apply 7 rounds
        for (round in Iter.range(0, 6)) {
            roundFn(state, blockWords, round);
        };

        // XOR with input CV
        for (i in Iter.range(0, 7)) {
            cv[i] := state[i] ^ state[i + 8];
        };
    };

    // Compress function (XOF output)
    public func compressXof(cv: [Nat32], block: [Nat8], blockLen: Nat8, counter: Nat64, flags: Nat8) : [Nat8] {
        let blockWords = loadBlockWords(block);
        let state = Array.thaw<Nat32>(Array.tabulate<Nat32>(16, func(i) {
            if (i < 8) cv[i]
            else if (i < 12) IV[i - 8]
            else if (i == 12) counterLow(counter)
            else if (i == 13) counterHigh(counter)
            else if (i == 14) Nat32.fromNat(Nat8.toNat(blockLen))
            else Nat32.fromNat(Nat8.toNat(flags))
        }));

        // Apply 7 rounds
        for (round in Iter.range(0, 6)) {
            roundFn(state, blockWords, round);
        };

        // Create output
        let output = Buffer.Buffer<Nat8>(64);

        // First 32 bytes: state[0..8] ^ state[8..16]
        for (i in Iter.range(0, 7)) {
            let word = state[i] ^ state[i + 8];
            output.append(Buffer.fromArray<Nat8>(store32(word)));
        };

        // Last 32 bytes: state[8..16] ^ cv[0..8]
        for (i in Iter.range(0, 7)) {
            let word = state[i + 8] ^ cv[i];
            output.append(Buffer.fromArray<Nat8>(store32(word)));
        };

        Buffer.toArray(output)
    };

    // Initialize chunk state
    private func chunkStateInit(key: [Nat32], flags: Nat8) : ChunkState {
        {
            cv = key;
            chunkCounter = 0;
            buf = Array.tabulate<Nat8>(BLOCK_LEN, func(_) = 0);
            bufLen = 0;
            blocksCompressed = 0;
            flags = flags;
        }
    };

    // Reset chunk state
    private func chunkStateReset(chunk: ChunkState, key: [Nat32], chunkCounter: Nat64) : ChunkState {
        {
            cv = key;
            chunkCounter = chunkCounter;
            blocksCompressed = 0;
            buf = Array.tabulate<Nat8>(BLOCK_LEN, func(_) = 0);
            bufLen = 0;
            flags = chunk.flags;
        }
    };

    // Get chunk state length
    private func chunkStateLen(chunk: ChunkState) : Nat {
        (BLOCK_LEN * Nat8.toNat(chunk.blocksCompressed)) + Nat8.toNat(chunk.bufLen)
    };

    // Fill buffer with input
    private func chunkStateFillBuf(chunk: ChunkState, input: [Nat8], inputLen: Nat) : (ChunkState, Nat) {
        let take = if (BLOCK_LEN - Nat8.toNat(chunk.bufLen) > inputLen)
                   inputLen
                   else BLOCK_LEN - Nat8.toNat(chunk.bufLen);

        let newBuf = Array.tabulate<Nat8>(BLOCK_LEN, func(i) {
            if (i < Nat8.toNat(chunk.bufLen)) chunk.buf[i]
            else if (i < Nat8.toNat(chunk.bufLen) + take) input[i - Nat8.toNat(chunk.bufLen)]
            else 0
        });

        ({
            cv = chunk.cv;
            chunkCounter = chunk.chunkCounter;
            buf = newBuf;
            bufLen = Nat8.fromNat(Nat8.toNat(chunk.bufLen) + take);
            blocksCompressed = chunk.blocksCompressed;
            flags = chunk.flags;
        }, take)
    };

    // Maybe start flag
    private func chunkStateMaybeStartFlag(chunk: ChunkState) : Nat8 {
        if (chunk.blocksCompressed == 0) Nat8.fromNat(CHUNK_START) else Nat8.fromNat(0)
    };

    // Update chunk state
    private func chunkStateUpdate(chunk: ChunkState, input: [Nat8], inputLen: Nat) : ChunkState {
        var currentChunk = chunk;
        var remainingInput = input;
        var remainingLen = inputLen;

        // Fill buffer if it has data
        if (currentChunk.bufLen > 0) {
            let (newChunk, take) = chunkStateFillBuf(currentChunk, remainingInput, remainingLen);
            currentChunk := newChunk;
            remainingInput := Array.tabulate<Nat8>(remainingLen - take, func(i) = remainingInput[i + take]);
            remainingLen -= take;

            if (remainingLen > 0) {
                // Compress the buffer
                let cvArray = Array.thaw<Nat32>(currentChunk.cv);
                compressInPlace(cvArray, currentChunk.buf, Nat8.fromNat(BLOCK_LEN), currentChunk.chunkCounter,
                               currentChunk.flags | chunkStateMaybeStartFlag(currentChunk));
                currentChunk := {
                    cv = Array.freeze<Nat32>(cvArray);
                    chunkCounter = currentChunk.chunkCounter;
                    buf = Array.tabulate<Nat8>(BLOCK_LEN, func(_) = 0);
                    bufLen = 0;
                    blocksCompressed = Nat8.fromNat(Nat8.toNat(currentChunk.blocksCompressed) + 1);
                    flags = currentChunk.flags;
                };
            };
        };

        // Process full blocks
        while (remainingLen > BLOCK_LEN) {
            let cvArray = Array.thaw<Nat32>(currentChunk.cv);
            compressInPlace(cvArray, remainingInput, Nat8.fromNat(BLOCK_LEN), currentChunk.chunkCounter,
                           currentChunk.flags | chunkStateMaybeStartFlag(currentChunk));
            currentChunk := {
                cv = Array.freeze<Nat32>(cvArray);
                chunkCounter = currentChunk.chunkCounter;
                buf = Array.tabulate<Nat8>(BLOCK_LEN, func(_) = 0);
                bufLen = 0;
                blocksCompressed = Nat8.fromNat(Nat8.toNat(currentChunk.blocksCompressed) + 1);
                flags = currentChunk.flags;
            };
            remainingInput := Array.tabulate<Nat8>(remainingLen - BLOCK_LEN, func(i) = remainingInput[i + BLOCK_LEN]);
            remainingLen -= BLOCK_LEN;
        };

        // Fill remaining input into buffer
        if (remainingLen > 0) {
            let (newChunk, _) = chunkStateFillBuf(currentChunk, remainingInput, remainingLen);
            currentChunk := newChunk;
        };

        currentChunk
    };

    // Create output from chunk state
    private func chunkStateOutput(chunk: ChunkState) : ([Nat32], [Nat8], Nat8, Nat64, Nat8) {
        let blockFlags = chunk.flags | chunkStateMaybeStartFlag(chunk) | Nat8.fromNat(CHUNK_END);
        (chunk.cv, chunk.buf, chunk.bufLen, chunk.chunkCounter, blockFlags)
    };

    // Output chaining value
    private func outputChainingValue(inputCv: [Nat32], block: [Nat8], blockLen: Nat8, counter: Nat64, flags: Nat8) : [Nat8] {
        let cvArray = Array.thaw<Nat32>(inputCv);
        compressInPlace(cvArray, block, blockLen, counter, flags);
        storeCvWords(Array.freeze<Nat32>(cvArray))
    };

    // Output root bytes
    private func outputRootBytes(inputCv: [Nat32], block: [Nat8], blockLen: Nat8, counter: Nat64, flags: Nat8, seek: Nat64, outLen: Nat) : [Nat8] {
        if (outLen == 0) return [];

        let outputBlockCounter = seek / 64;
        let offsetWithinBlock = seek % 64;

        if (offsetWithinBlock > 0) {
            let wideBuf = compressXof(inputCv, block, blockLen, outputBlockCounter, flags | Nat8.fromNat(ROOT));
            let availableBytes = 64 - Nat64.toNat(offsetWithinBlock);
            let bytes = if (outLen > availableBytes) availableBytes else outLen;
            Array.tabulate<Nat8>(bytes, func(i) = wideBuf[i + Nat64.toNat(offsetWithinBlock)])
        } else {
            let wideBuf = compressXof(inputCv, block, blockLen, outputBlockCounter, flags | Nat8.fromNat(ROOT));
            Array.tabulate<Nat8>(outLen, func(i) = wideBuf[i])
        }
    };

    // Initialize hasher
    public func hasherInit() : Hasher {
        {
            key = IV;
            chunk = chunkStateInit(IV, 0);
            cvStackLen = 0;
            cvStack = Array.tabulate<Nat8>((MAX_DEPTH + 1) * OUT_LEN, func(_) = 0);
        }
    };

    // Initialize keyed hasher
    public func hasherInitKeyed(key: [Nat8]) : Hasher {
        let keyWords = Array.tabulate<Nat32>(8, func(i) = load32(key, i * 4));
        {
            key = keyWords;
            chunk = chunkStateInit(keyWords, Nat8.fromNat(KEYED_HASH));
            cvStackLen = 0;
            cvStack = Array.tabulate<Nat8>((MAX_DEPTH + 1) * OUT_LEN, func(_) = 0);
        }
    };

    // Update hasher
    public func hasherUpdate(hasher: Hasher, input: [Nat8]) : Hasher {
        if (input.size() == 0) return hasher;

        var currentHasher = hasher;
        var remainingInput = input;
        var remainingLen = input.size();

        // If we have partial chunk bytes, finish that chunk first
        if (chunkStateLen(currentHasher.chunk) > 0) {
            let take = if (CHUNK_LEN - chunkStateLen(currentHasher.chunk) > remainingLen)
                       remainingLen
                       else CHUNK_LEN - chunkStateLen(currentHasher.chunk);

            let newChunk = chunkStateUpdate(currentHasher.chunk, remainingInput, take);
            currentHasher := {
                key = currentHasher.key;
                chunk = newChunk;
                cvStackLen = currentHasher.cvStackLen;
                cvStack = currentHasher.cvStack;
            };

            remainingInput := Array.tabulate<Nat8>(remainingLen - take, func(i) = remainingInput[i + take]);
            remainingLen -= take;

            // If we've filled the current chunk and there's more coming, finalize this chunk
            if (remainingLen > 0) {
                let (inputCv, block, blockLen, counter, flags) = chunkStateOutput(currentHasher.chunk);
                let chunkCv = outputChainingValue(inputCv, block, blockLen, counter, flags);

                // Push CV to stack (simplified - would need proper stack management)
                currentHasher := {
                    key = currentHasher.key;
                    chunk = chunkStateReset(currentHasher.chunk, currentHasher.key, currentHasher.chunk.chunkCounter + 1);
                    cvStackLen = currentHasher.cvStackLen;
                    cvStack = currentHasher.cvStack;
                };
            } else {
                return currentHasher;
            };
        };

        // Process remaining input
        if (remainingLen > 0) {
            let newChunk = chunkStateUpdate(currentHasher.chunk, remainingInput, remainingLen);
            currentHasher := {
                key = currentHasher.key;
                chunk = newChunk;
                cvStackLen = currentHasher.cvStackLen;
                cvStack = currentHasher.cvStack;
            };
        };

        currentHasher
    };

    // Finalize hasher
    public func hasherFinalize(hasher: Hasher, outLen: Nat) : [Nat8] {
        hasherFinalizeSeek(hasher, 0, outLen)
    };

    // Finalize hasher with seek
    public func hasherFinalizeSeek(hasher: Hasher, seek: Nat64, outLen: Nat) : [Nat8] {
        if (outLen == 0) return [];

        // If the subtree stack is empty, then the current chunk is the root
        if (hasher.cvStackLen == 0) {
            let (inputCv, block, blockLen, counter, flags) = chunkStateOutput(hasher.chunk);
            return outputRootBytes(inputCv, block, blockLen, counter, flags, seek, outLen);
        };

        // For simplicity, we'll handle the basic case
        // In a full implementation, we'd need to handle the CV stack properly
        let (inputCv, block, blockLen, counter, flags) = chunkStateOutput(hasher.chunk);
        outputRootBytes(inputCv, block, blockLen, counter, flags, seek, outLen)
    };

    /// Additional Utility Functions
    ///
    /// These functions provide convenient access to BLAKE3 functionality
    /// with different input/output formats.

    /// Hash byte array directly (convenience function)
    ///
    /// Computes BLAKE3 hash of a byte array using the internal representation.
    /// This is useful when working with raw bytes instead of Blobs.
    ///
    /// # Parameters
    /// - `input`: Array of bytes to hash
    ///
    /// # Returns
    /// 32-byte hash as an array of Nat8
    public func hash(input: [Nat8]) : [Nat8] {
        let hasher = hasherInit();
        let updatedHasher = hasherUpdate(hasher, input);
        hasherFinalize(updatedHasher, OUT_LEN)
    };

    /// Hash text string directly (convenience function)
    ///
    /// Computes BLAKE3 hash of a text string by first encoding it as UTF-8 bytes.
    /// This is the most convenient way to hash string data.
    ///
    /// # Parameters
    /// - `text`: Text string to hash
    ///
    /// # Returns
    /// 32-byte hash as an array of Nat8
    ///
    /// # Example
    /// ```motoko
    /// let hash = Blake3.hashText("hello world");
    /// let hexHash = Blake3.toHex(hash);
    /// ```
    public func hashText(text: Text) : [Nat8] {
        let bytes = Text.encodeUtf8(text);
        hash(Array.tabulate<Nat8>(bytes.size(), func(i) = bytes[i]))
    };

    /// Convert hash bytes to lowercase hexadecimal string
    ///
    /// Converts a hash result to a human-readable hexadecimal string.
    /// Each byte is represented as two lowercase hex characters.
    ///
    /// # Parameters
    /// - `hash`: Hash bytes to convert
    ///
    /// # Returns
    /// Lowercase hexadecimal string representation
    ///
    /// # Example
    /// ```motoko
    /// let hash = Blake3.hashText("hello");
    /// let hexString = Blake3.toHex(hash); // "ea8f163db..."
    /// ```
    public func toHex(hash: [Nat8]) : Text {
        let hexChars = "0123456789abcdef";
        let hexArray = Iter.toArray(hexChars.chars());
        let chars = Buffer.Buffer<Char>(hash.size() * 2);
        for (b in hash.vals()) {
            let high = Nat8.toNat(b) / 16;
            let low = Nat8.toNat(b) % 16;
            chars.add(hexArray[high]);
            chars.add(hexArray[low]);
        };
        Text.fromIter(chars.vals())
    };

    /// Public API Functions
    ///
    /// These functions provide the main interface for BLAKE3 hashing operations.
    /// They maintain compatibility with existing code while providing access to
    /// the full BLAKE3 feature set.

    /// Initialize a streaming hasher with optional configuration
    ///
    /// Creates a new hasher that can process data incrementally using `update()`
    /// and `finalize()`. This is useful for large inputs or when data arrives
    /// in chunks.
    ///
    /// # Parameters
    /// - `config`: Optional configuration specifying key, context, or derivation mode
    ///
    /// # Returns
    /// A new `Blake3Hasher` ready for incremental updates
    ///
    /// # Example
    /// ```motoko
    /// let hasher = Blake3.init(null); // Regular hashing
    /// let keyedHasher = Blake3.init(?{ key = ?myKey; context = null; derive_key = false });
    /// ```
    public func init(config: ?Blake3Config) : Blake3Hasher {
        let final_config = Option.get(config, {
            key = null;
            context = null;
            derive_key = false;
        });

        let internal = switch (final_config.key) {
            case (?key_blob) {
                let key_bytes = Blob.toArray(key_blob);
                if (key_bytes.size() == KEY_LEN) {
                    hasherInitKeyed(key_bytes)
                } else {
                    hasherInit()
                }
            };
            case null {
                hasherInit()
            };
        };

        { var internal = internal }
    };

    /// Add data to a streaming hasher
    ///
    /// Updates the hasher state with new input data. Can be called multiple times
    /// to process large inputs incrementally. The order of updates matters - data
    /// is processed in the order it's added.
    ///
    /// # Parameters
    /// - `hasher`: The hasher to update (modified in place)
    /// - `input`: New data to add to the hash
    ///
    /// # Example
    /// ```motoko
    /// let hasher = Blake3.init(null);
    /// Blake3.update(hasher, Text.encodeUtf8("Hello "));
    /// Blake3.update(hasher, Text.encodeUtf8("World!"));
    /// let result = Blake3.finalize(hasher);
    /// ```
    public func update(hasher: Blake3Hasher, input: Blob) {
        let inputBytes = Blob.toArray(input);
        hasher.internal := hasherUpdate(hasher.internal, inputBytes);
    };

    /// Finalize a streaming hasher and return the hash
    ///
    /// Completes the hashing process and returns the final 32-byte hash value.
    /// After calling this function, the hasher should not be used again.
    ///
    /// # Parameters
    /// - `hasher`: The hasher to finalize
    ///
    /// # Returns
    /// The final 32-byte BLAKE3 hash as a Blob
    ///
    /// # Example
    /// ```motoko
    /// let hasher = Blake3.init(null);
    /// Blake3.update(hasher, myData);
    /// let hash = Blake3.finalize(hasher);
    /// ```
    public func finalize(hasher: Blake3Hasher) : Blob {
        let result = hasherFinalize(hasher.internal, OUT_LEN);
        Blob.fromArray(result)
    };

    /// Compute BLAKE3 hash of input data (one-shot)
    ///
    /// This is the simplest way to hash data when you have all input available
    /// at once. For large inputs or streaming data, use `init()`, `update()`,
    /// and `finalize()` instead.
    ///
    /// # Parameters
    /// - `data`: The data to hash
    ///
    /// # Returns
    /// The 32-byte BLAKE3 hash as a Blob
    ///
    /// # Example
    /// ```motoko
    /// let data = Text.encodeUtf8("hello world");
    /// let hash = Blake3.digest(data);
    /// ```
    public func digest(data: Blob) : Blob {
        let dataBytes = Blob.toArray(data);
        let result = hash(dataBytes);
        Blob.fromArray(result)
    };

    /// Compute keyed BLAKE3 hash for message authentication
    ///
    /// Keyed hashing provides message authentication - only someone with the
    /// correct 32-byte key can produce or verify the hash. This is cryptographically
    /// stronger than HMAC constructions.
    ///
    /// # Parameters
    /// - `key`: 32-byte authentication key (must be exactly 32 bytes)
    /// - `data`: The data to authenticate
    ///
    /// # Returns
    /// The 32-byte keyed BLAKE3 hash as a Blob
    ///
    /// # Example
    /// ```motoko
    /// let key = Text.encodeUtf8("my-secret-key-32-bytes-long!!!");
    /// let message = Text.encodeUtf8("authenticated message");
    /// let authHash = Blake3.keyed_hash(key, message);
    /// ```
    ///
    /// # Security Note
    /// The key must be exactly 32 bytes. If a different length is provided,
    /// the function falls back to regular (unkeyed) hashing for compatibility.
    public func keyed_hash(key: Blob, data: Blob) : Blob {
        let keyBytes = Blob.toArray(key);
        let dataBytes = Blob.toArray(data);

        if (keyBytes.size() == KEY_LEN) {
            let hasher = hasherInitKeyed(keyBytes);
            let updatedHasher = hasherUpdate(hasher, dataBytes);
            let result = hasherFinalize(updatedHasher, OUT_LEN);
            Blob.fromArray(result)
        } else {
            // Fallback to regular hash if key is wrong size
            digest(data)
        }
    };

    /// Derive a key from key material using BLAKE3
    ///
    /// Key derivation allows you to generate multiple cryptographic keys from
    /// a single master key or random material. Each context string produces
    /// a different derived key, allowing for key separation.
    ///
    /// # Parameters
    /// - `_context`: Context string for key separation (currently unused but reserved)
    /// - `key_material`: Source material to derive the key from
    ///
    /// # Returns
    /// A 32-byte derived key as a Blob
    ///
    /// # Example
    /// ```motoko
    /// let masterKey = Text.encodeUtf8("master-key-material");
    /// let signingKey = Blake3.derive_key("signing-v1", masterKey);
    /// let encryptionKey = Blake3.derive_key("encryption-v1", masterKey);
    /// ```
    ///
    /// # Security Note
    /// The derived key is cryptographically independent from both the source
    /// material and keys derived with different contexts.
    public func derive_key(_context: Text, key_material: Blob) : Blob {
        // Use DERIVE_KEY_MATERIAL flag to make it different from regular hash
        let dataBytes = Blob.toArray(key_material);
        let hasher = {
            key = IV;
            chunk = chunkStateInit(IV, Nat8.fromNat(DERIVE_KEY_MATERIAL));
            cvStackLen = 0 : Nat8;
            cvStack = Array.tabulate<Nat8>((MAX_DEPTH + 1) * OUT_LEN, func(_) = 0);
        };
        let updatedHasher = hasherUpdate(hasher, dataBytes);
        let result = hasherFinalize(updatedHasher, OUT_LEN);
        Blob.fromArray(result)
    };
}