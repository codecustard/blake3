import Array "mo:base/Array";
import Blob "mo:base/Blob";
import Buffer "mo:base/Buffer";
import Nat8 "mo:base/Nat8";
import Nat32 "mo:base/Nat32";
import Nat64 "mo:base/Nat64";
import Option "mo:base/Option";

module Blake3 {

    // BLAKE3 constants
    private let BLOCK_LEN : Nat = 64;
    private let _CHUNK_LEN : Nat = 1024;
    private let _OUT_LEN : Nat = 32;
    private let KEY_LEN : Nat = 32;
    private let MAX_DEPTH : Nat = 54;

    // BLAKE3 IV (same as ChaCha20)
    private let IV : [Nat32] = [
        0x6A09E667, 0xBB67AE85, 0x3C6EF372, 0xA54FF53A,
        0x510E527F, 0x9B05688C, 0x1F83D9AB, 0x5BE0CD19
    ];

    // Message schedule permutations for 7 rounds
    private let MSG_SCHEDULE : [[Nat]] = [
        [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15],
        [2, 6, 3, 10, 7, 0, 4, 13, 1, 11, 12, 5, 9, 14, 15, 8],
        [3, 4, 10, 12, 13, 2, 7, 14, 6, 5, 9, 0, 11, 15, 8, 1],
        [10, 7, 12, 9, 14, 3, 13, 15, 4, 0, 11, 2, 5, 8, 1, 6],
        [12, 13, 9, 11, 15, 10, 14, 8, 7, 2, 5, 3, 0, 1, 6, 4],
        [9, 14, 11, 5, 8, 12, 15, 1, 13, 3, 0, 10, 2, 6, 4, 7],
        [11, 15, 5, 0, 1, 9, 8, 6, 14, 10, 2, 12, 3, 4, 7, 13]
    ];

    // Domain separation flags
    private let CHUNK_START : Nat8 = 1;
    private let CHUNK_END : Nat8 = 2;
    private let _PARENT : Nat8 = 4;
    private let ROOT : Nat8 = 8;
    private let KEYED_HASH : Nat8 = 16;
    private let _DERIVE_KEY_CONTEXT : Nat8 = 32;
    private let DERIVE_KEY_MATERIAL : Nat8 = 64;

    public type Blake3Config = {
        key: ?Blob;
        context: ?Text;
        derive_key: Bool;
    };

    // Chunk state for processing 1024-byte chunks
    private type ChunkState = {
        var chaining_value: [var Nat32];
        var chunk_counter: Nat64;
        var block: [var Nat8];
        var block_len: Nat8;
        var blocks_compressed: Nat8;
        flags: Nat8;
    };

    public type Blake3Hasher = {
        chunk_state: ChunkState;
        key: [Nat32];
        cv_stack: Buffer.Buffer<[Nat32]>;
        var cv_stack_len: Nat8;
        flags: Nat8;
    };

    // Rotate right 32-bit
    private func rotr32(w: Nat32, c: Nat) : Nat32 {
        let shift_right = Nat32.fromNat(c);
        let shift_left = Nat32.fromNat(32 - c);
        (w >> shift_right) | (w << shift_left)
    };

    // Load 32-bit word from bytes (little-endian)
    private func load32(bytes: [Nat8], offset: Nat) : Nat32 {
        if (offset + 4 > bytes.size()) return 0;
        let b0 = Nat32.fromNat(Nat8.toNat(bytes[offset]));
        let b1 = Nat32.fromNat(Nat8.toNat(bytes[offset + 1]));
        let b2 = Nat32.fromNat(Nat8.toNat(bytes[offset + 2]));
        let b3 = Nat32.fromNat(Nat8.toNat(bytes[offset + 3]));
        b0 | (b1 << 8) | (b2 << 16) | (b3 << 24)
    };

    // Store 32-bit word to bytes (little-endian)
    private func store32(value: Nat32, bytes: [var Nat8], offset: Nat) {
        if (offset + 4 > bytes.size()) return;
        bytes[offset] := Nat8.fromNat(Nat32.toNat(value & 0xFF));
        bytes[offset + 1] := Nat8.fromNat(Nat32.toNat((value >> 8) & 0xFF));
        bytes[offset + 2] := Nat8.fromNat(Nat32.toNat((value >> 16) & 0xFF));
        bytes[offset + 3] := Nat8.fromNat(Nat32.toNat((value >> 24) & 0xFF));
    };

    // BLAKE3 quarter round (g function from spec)
    private func g(state: [var Nat32], a: Nat, b: Nat, c: Nat, d: Nat, x: Nat32, y: Nat32) {
        state[a] := state[a] +% state[b] +% x;
        state[d] := rotr32(state[d] ^ state[a], 16);
        state[c] := state[c] +% state[d];
        state[b] := rotr32(state[b] ^ state[c], 12);
        state[a] := state[a] +% state[b] +% y;
        state[d] := rotr32(state[d] ^ state[a], 8);
        state[c] := state[c] +% state[d];
        state[b] := rotr32(state[b] ^ state[c], 7);
    };

    // BLAKE3 round function
    private func round_fn(state: [var Nat32], m: [Nat32], schedule: [Nat]) {
        // Column round
        g(state, 0, 4, 8, 12, m[schedule[0]], m[schedule[1]]);
        g(state, 1, 5, 9, 13, m[schedule[2]], m[schedule[3]]);
        g(state, 2, 6, 10, 14, m[schedule[4]], m[schedule[5]]);
        g(state, 3, 7, 11, 15, m[schedule[6]], m[schedule[7]]);
        // Diagonal round
        g(state, 0, 5, 10, 15, m[schedule[8]], m[schedule[9]]);
        g(state, 1, 6, 11, 12, m[schedule[10]], m[schedule[11]]);
        g(state, 2, 7, 8, 13, m[schedule[12]], m[schedule[13]]);
        g(state, 3, 4, 9, 14, m[schedule[14]], m[schedule[15]]);
    };

    // BLAKE3 compression function
    private func compress(
        chaining_value: [Nat32],
        block_words: [Nat32],
        counter: Nat64,
        block_len: Nat8,
        flags: Nat8
    ) : [Nat32] {
        var state: [var Nat32] = [var
            chaining_value[0], chaining_value[1], chaining_value[2], chaining_value[3],
            chaining_value[4], chaining_value[5], chaining_value[6], chaining_value[7],
            IV[0], IV[1], IV[2], IV[3],
            Nat32.fromNat(Nat64.toNat(counter & 0xFFFFFFFF)),
            Nat32.fromNat(Nat64.toNat(counter >> 32)),
            Nat32.fromNat(Nat8.toNat(block_len)),
            Nat32.fromNat(Nat8.toNat(flags))
        ];

        // 7 rounds
        var round = 0;
        while (round < 7) {
            round_fn(state, block_words, MSG_SCHEDULE[round]);
            round += 1;
        };

        // XOR first and second halves
        [state[0] ^ state[8], state[1] ^ state[9], state[2] ^ state[10], state[3] ^ state[11],
         state[4] ^ state[12], state[5] ^ state[13], state[6] ^ state[14], state[7] ^ state[15]]
    };

    // Load block as 16 words
    private func words_from_block(block: [Nat8]) : [Nat32] {
        var words: [var Nat32] = [var 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];
        var i = 0;
        while (i < 16) {
            words[i] := load32(block, i * 4);
            i += 1;
        };
        Array.freeze(words)
    };

    // Initialize chunk state
    private func chunk_state_init(key: [Nat32], flags: Nat8) : ChunkState {
        var cv: [var Nat32] = [var key[0], key[1], key[2], key[3], key[4], key[5], key[6], key[7]];
        var block: [var Nat8] = [var
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0
        ];
        {
            var chaining_value = cv;
            var chunk_counter = 0;
            var block = block;
            var block_len = 0;
            var blocks_compressed = 0;
            flags = flags;
        }
    };

    // Update chunk state with input
    private func chunk_state_update(state: ChunkState, input: [Nat8]) {
        var input_offset = 0;
        while (input_offset < input.size()) {
            // Fill current block
            if (Nat8.toNat(state.block_len) < BLOCK_LEN) {
                let block_len_nat = Nat8.toNat(state.block_len);
                assert(BLOCK_LEN >= block_len_nat);
                let want : Nat = BLOCK_LEN - block_len_nat;
                assert(input.size() >= input_offset);
                let remaining : Nat = input.size() - input_offset;
                let take = if (remaining < want) remaining else want;
                var i = 0;
                while (i < take) {
                    state.block[Nat8.toNat(state.block_len) + i] := input[input_offset + i];
                    i += 1;
                };
                state.block_len := Nat8.fromNat(Nat8.toNat(state.block_len) + take);
                input_offset += take;
            };

            // If block is full, compress it
            if (Nat8.toNat(state.block_len) == BLOCK_LEN) {
                let block_words = words_from_block(Array.freeze(state.block));
                let start_flag = if (state.blocks_compressed == 0) CHUNK_START else Nat8.fromNat(0);
                let cv = compress(
                    Array.freeze(state.chaining_value),
                    block_words,
                    state.chunk_counter,
                    state.block_len,
                    state.flags | start_flag
                );
                state.chaining_value := [var cv[0], cv[1], cv[2], cv[3], cv[4], cv[5], cv[6], cv[7]];
                state.blocks_compressed += 1;
                state.block_len := 0;
            };
        };
    };

    // Output from chunk state
    private func chunk_state_output(state: ChunkState) : [Nat32] {
        let block_words = words_from_block(Array.freeze(state.block));
        let start_flag = if (state.blocks_compressed == 0) CHUNK_START else Nat8.fromNat(0);
        compress(
            Array.freeze(state.chaining_value),
            block_words,
            state.chunk_counter,
            state.block_len,
            state.flags | start_flag | CHUNK_END | ROOT
        )
    };

    // Initialize hasher
    public func init(config: ?Blake3Config) : Blake3Hasher {
        let final_config = Option.get(config, {
            key = null;
            context = null;
            derive_key = false;
        });

        var key_words: [Nat32] = IV;
        var flags: Nat8 = 0;

        // Handle keyed hashing
        switch (final_config.key) {
            case (?key_blob) {
                let key_bytes = Blob.toArray(key_blob);
                if (key_bytes.size() == KEY_LEN) {
                    var temp_key: [var Nat32] = [var 0, 0, 0, 0, 0, 0, 0, 0];
                    var i = 0;
                    while (i < 8) {
                        temp_key[i] := load32(key_bytes, i * 4);
                        i += 1;
                    };
                    key_words := Array.freeze(temp_key);
                    flags := flags | KEYED_HASH;
                };
            };
            case null {};
        };

        // Handle key derivation
        if (final_config.derive_key) {
            flags := flags | DERIVE_KEY_MATERIAL;
        };

        {
            chunk_state = chunk_state_init(key_words, flags);
            key = key_words;
            cv_stack = Buffer.Buffer<[Nat32]>(MAX_DEPTH);
            var cv_stack_len = 0;
            flags = flags;
        }
    };

    // Update hasher with input
    public func update(hasher: Blake3Hasher, input: Blob) {
        chunk_state_update(hasher.chunk_state, Blob.toArray(input));
    };

    // Finalize and get output
    public func finalize(hasher: Blake3Hasher) : Blob {
        let output = chunk_state_output(hasher.chunk_state);

        // Convert to bytes
        var result: [var Nat8] = [var
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0
        ];

        var i = 0;
        while (i < 8) {
            store32(output[i], result, i * 4);
            i += 1;
        };

        Blob.fromArray(Array.freeze(result))
    };

    // One-shot hash
    public func hash(data: Blob, config: ?Blake3Config) : Blob {
        let hasher = init(config);
        update(hasher, data);
        finalize(hasher)
    };

    // Simple digest
    public func digest(data: Blob) : Blob {
        hash(data, null)
    };

    // Keyed hash
    public func keyed_hash(key: Blob, data: Blob) : Blob {
        hash(data, ?{ key = ?key; context = null; derive_key = false })
    };

    // Key derivation
    public func derive_key(context: Text, key_material: Blob) : Blob {
        hash(key_material, ?{ key = null; context = ?context; derive_key = true })
    };
}