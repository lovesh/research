from ethereum.utils import sha3, encode_hex

class EphemDB():
    def __init__(self, kv=None):
        self.reads = 0
        self.writes = 0
        self.kv = kv or {}

    def get(self, k):
        self.reads += 1
        return self.kv.get(k, None)

    def put(self, k, v):
        self.writes += 1
        self.kv[k] = v

    def delete(self, k):
        del self.kv[k]


zero = b'\x00' * 32
# Hashes of empty subtrees
zerohashes = [zero]
for i in range(256):
    zerohashes.insert(0, sha3(zerohashes[0] + zerohashes[0]))

# Create a new empty tree
def new_tree(db):
    return zerohashes[0]

# Convert a binary key into an integer path value
def key_to_path(k):
    return int.from_bytes(k, 'big')

tt256 = 2**256
tt256m1 = tt256 - 1

# And convert back
def path_to_key(k):
    return (k & tt256m1).to_bytes(32, 'big')


def get(db, root, key, proof=None):
    return _get(db, root, key_to_path(key), proof)


# Read a key from a given tree
def _get(db, root, path, proof=None):
    assert proof is None or isinstance(proof, list)
    v = root
    for i in range(256):
        if v == zerohashes[i]:
            return b'\x00' * 32
        child = db.get(v)
        if proof is not None:
            proof.append(child)
        if len(child) == 65:
            # Consider only last 256 digits of path
            #if (path % tt256) == key_to_path(child[1:33]):
            #if (path & tt256m1) == key_to_path(child[1:33]):
            if reduce(path) == key_to_path(child[1:33]):
                return child[33:]
            else:
                return zero
        else:
            if (path >> 255) & 1:
                v = child[32:]
            else:
                v = child[:32]

        path <<= 1

    return v


def verify_proof(proof, root, key, value):
    return _verify_proof(proof, root, key_to_path(key), value)


def _verify_proof(proof, root, path, value):
    if root == zerohashes[0]:
        return len(proof) == 0

    prev_hash = root

    for proof_node in proof:
        if len(proof_node) == 65:
            # if (path % tt256) == key_to_path(proof_node[1:33]):
            if (path & tt256m1) == key_to_path(proof_node[1:33]):
                return proof_node[33:] == value
            else:
                return zero == value
        else:
            if sha3(proof_node) != prev_hash:
                return False

            if (path >> 255) & 1:
                prev_hash = proof_node[32:]
            else:
                prev_hash = proof_node[:32]

        path <<= 1

    return value == prev_hash if len(proof) == 256 else value == zero


# Make a root hash of a (sub)tree with a single key/value pair from empty tree
def make_single_key_hash(path, depth, value):
    if depth == 256:
        return value
    elif (path >> 255) & 1:
        # MSB is set, descend in right subtree and hash the result with empty left subtree
        return sha3(zerohashes[depth+1] + make_single_key_hash(path << 1, depth + 1, value))
    else:
        # MSB is unset, descend in left subtree and hash the result with empty right subtree
        return sha3(make_single_key_hash(path << 1, depth + 1, value) + zerohashes[depth+1])


# Make a root hash of a (sub)tree with two key/value pairs from tree with 1 key/value pair,
# and save intermediate nodes in the DB
def make_double_key_hash(db, path_for_new_key, path_for_existing_key, depth, new_value, existing_value):
    if depth == 256:
        raise Exception("Cannot fit two values into one slot!")
    if (path_for_new_key >> 255) & 1:
        # MSB is set, new value lies in right subtree
        if (path_for_existing_key >> 255) & 1:
            # Existing key-value pair is in right subtree, hence left subtree is empty
            child = zerohashes[depth+1] + make_double_key_hash(db,
                                                               path_for_new_key << 1,
                                                               path_for_existing_key << 1,
                                                               depth + 1, new_value, existing_value)
        else:
            # Existing key-value pair is in left subtree, create 2 subtrees with 1 key-value pair each
            L = make_single_key_hash(path_for_existing_key << 1, depth + 1, existing_value)
            R = make_single_key_hash(path_for_new_key << 1, depth + 1, new_value)
            db.put(L, b'\x01' + path_to_key(path_for_existing_key << 1) + existing_value)
            db.put(R, b'\x01' + path_to_key(path_for_new_key << 1) + new_value)
            child = L + R
    else:
        # MSB is unset, new value lies in left subtree
        if (path_for_existing_key >> 255) & 1:
            # Existing key-value pair is in right subtree, create 2 subtrees with 1 key-value pair each
            L = make_single_key_hash(path_for_new_key << 1, depth + 1, new_value)
            R = make_single_key_hash(path_for_existing_key << 1, depth + 1, existing_value)
            db.put(L, b'\x01' + path_to_key(path_for_new_key << 1) + new_value)
            db.put(R, b'\x01' + path_to_key(path_for_existing_key << 1) + existing_value)
            child = L + R
        else:
            # Existing key-value pair is in left subtree, hence right subtree is empty
            child = make_double_key_hash(db,
                                         path_for_new_key << 1,
                                         path_for_existing_key << 1,
                                         depth + 1, new_value, existing_value) \
                    + zerohashes[depth + 1]
    db.put(sha3(child), child)
    return sha3(child)


# Update a tree with a given key/value pair
def update(db, root, key, value):
    return _update(db, root, key_to_path(key), 0, value)


def _update(db, root, path, depth, value):
    if depth == 256:
        return value
    # Update an empty subtree: make a single-key subtree
    if root == zerohashes[depth]:
        new_root = make_single_key_hash(path, depth, value)
        db.put(new_root, b'\x01' + path_to_key(path) + value)
        return new_root
    child = db.get(root)
    # Update a single-key subtree: make a double-key subtree
    if len(child) == 65:        # 65 since 1 byte for designator, 32+32 for key+value
        origpath, origvalue = key_to_path(child[1:33]), child[33:]
        return make_double_key_hash(db, path, origpath, depth, value, origvalue)
    # Update a multi-key subtree: recurse down
    elif (path >> 255) & 1:
        # New value lies in right subtree so update right subtree
        new_child = child[:32] + _update(db, child[32:], path << 1, depth + 1, value)
        db.put(sha3(new_child), new_child)
        return sha3(new_child)
    else:
        # New value lies in left subtree so update left subtree
        new_child = _update(db, child[:32], path << 1, depth + 1, value) + child[32:]
        db.put(sha3(new_child), new_child)
        return sha3(new_child)


def multi_update(db, root, keys, values):
    for k, v in zip(keys, values):
        root = update(db, root, k, v)
    return root


def reduce(n):
    while n >= tt256:
        n = n - tt256
    return n