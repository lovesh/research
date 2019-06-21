from ethereum.utils import sha3, encode_hex


class EphemDB:
    def __init__(self, kv=None):
        self.reads = 0
        self.writes = 0
        self.kv = kv or {}

    def get(self, k):
        self.reads += 1
        return self.kv.get(k)

    def put(self, k, v):
        self.writes += 1
        self.kv[k] = v

    def delete(self, k):
        del self.kv[k]


hash_len = 32
tree_depth = 256
zero = b'\x00' * 32

zerohashes = [zero]
for _ in range(tree_depth):
    zerohashes.insert(0, sha3(zerohashes[0] + zerohashes[0]))


def new_tree(db):
    # h = zero
    # for i in range(tree_depth):
    #     newh = sha3(h + h)
    #     db.put(newh, h + h)
    #     h = newh
    # return h
    for i in range(tree_depth):
        db.put(zerohashes[i], zerohashes[i+1] + zerohashes[i+1])

    return zerohashes[0]


def key_to_path(k):
    """ Encode `k` as integer representing the leaf index """
    # o = 0
    # for c in k:
    #     o = (o << 8) + c
    # return o
    return int.from_bytes(k, 'big')


def descend(db, root, *path):
    v = root
    for p in path:
        if p:
            v = db.get(v)[32:]
        else:
            v = db.get(v)[:32]
    return v


def get(db, root, key):
    v = root
    path = key_to_path(key)
    for i in range(tree_depth):
        if (path >> tree_depth-1) & 1:
            v = db.get(v)[32:]
        else:
            v = db.get(v)[:32]
        path <<= 1
    return v


def update(db, root, key, value):
    v = root
    path = path2 = key_to_path(key)
    sidenodes = []
    for i in range(tree_depth):
        children = db.get(v)
        left, right = children[:32], children[32:]
        if (path >> tree_depth-1) & 1:
            # MSB is set, descend in right subtree
            sidenodes.append(left)
            v = right
        else:
            # MSB is unset, descend in left subtree
            sidenodes.append(right)
            v = left
        path <<= 1
    v = value
    for i in range(tree_depth):
        if (path2 & 1):
            newv = sha3(sidenodes[-1] + v)
            db.put(newv, sidenodes[-1] + v)
        else:
            newv = sha3(v + sidenodes[-1])
            db.put(newv, v + sidenodes[-1])
        path2 >>= 1
        v = newv
        sidenodes.pop()
    return v


def make_merkle_proof(db, root, key):
    v = root
    path = key_to_path(key)
    sidenodes = []
    for i in range(tree_depth):
        if (path >> tree_depth-1) & 1:
            sidenodes.append(db.get(v)[:32])
            v = db.get(v)[32:]
        else:
            sidenodes.append(db.get(v)[32:])
            v = db.get(v)[:32]
        path <<= 1
    return sidenodes


def verify_proof(proof, root, key, value):
    path = key_to_path(key)
    v = value
    for i in range(tree_depth):
        if (path & 1):
            newv = sha3(proof[-1-i] + v)
        else:
            newv = sha3(v + proof[-1-i])
        path >>= 1
        v = newv
    return root == v


def compress_proof(proof):
    bits = bytearray(32)
    oproof = b''
    for i, p in enumerate(proof):
        if p == zerohashes[i+1]:
            bits[i // 8] ^= 1 << i % 8
        else:
            oproof += p
    return bytes(bits) + oproof


def decompress_proof(oproof):
    proof = []
    bits = bytearray(oproof[:32])
    pos = 32
    for i in range(tree_depth):
        if bits[i // 8] & (1 << (i % 8)):
            proof.append(zerohashes[i+1])
        else:
            proof.append(oproof[pos: pos + 32])
            pos += 32
    return proof
