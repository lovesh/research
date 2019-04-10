from ethereum.utils import sha3, encode_hex


# Tree with each node having 4 children

class EphemDB:
    def __init__(self, kv=None):
        self.kv = kv or {}

    def get(self, k):
        return self.kv.get(k, None)

    def put(self, k, v):
        self.kv[k] = v

    def delete(self, k):
        del self.kv[k]


hash_len = 32
tree_depth = 128
zero = b'\x00' * 32


def hash_4_elems(e1, e2, e3, e4):
    return sha3(e1+e2+e3+e4)


zerohashes = [zero]
for _ in range(tree_depth):
    zerohashes.insert(0, hash_4_elems(*[zerohashes[0]]*4))


def new_tree(db):
    # h = zero
    # for i in range(tree_depth):
    #     newv = [h]*4
    #     newh = hash_4_elems(*newv)
    #     db.put(newh, newv)
    #     h = newh
    # return h

    for i in range(tree_depth):
        db.put(zerohashes[i], [zerohashes[i+1]]*4)

    return zerohashes[0]


def key_to_path(k):
    """ Encode `k` as base 4 digits representing the leaf index. Big endian representation """
    n = int.from_bytes(k, 'big')
    base_4_repr = []
    while n != 0:
        base_4_repr.append(n % 4)
        n = n >> 2

    while len(base_4_repr) < tree_depth:
        base_4_repr.append(0)

    base_4_repr.reverse()
    return base_4_repr


def get(db, root, key):
    v = root
    path = key_to_path(key)
    for d in path:
        children = db.get(v)
        v = children[d]
    return v


def update(db, root, key, value):
    v = root
    path = key_to_path(key)
    sidenodes = []
    for d in path:
        children = db.get(v)
        v = children[d]
        sidenodes.append([c for i, c in enumerate(children) if i != d])

    v = value
    for d in reversed(path):
        new_val = sidenodes.pop()
        new_val.insert(d, v)
        new_h = hash_4_elems(*new_val)
        db.put(new_h, new_val)
        v = new_h

    return v


def make_merkle_proof(db, root, key):
    v = root
    path = key_to_path(key)
    sidenodes = []
    for d in path:
        children = db.get(v)
        v = children[d]
        sidenodes.append([c for i, c in enumerate(children) if i != d])
    return sidenodes


def verify_proof(proof, root, key, value):
    path = key_to_path(key)
    v = value
    for i, d in enumerate(reversed(path)):
        new_val = proof[-1-i][:]
        new_val.insert(d, v)
        new_h = hash_4_elems(*new_val)
        v = new_h
    return root == v

