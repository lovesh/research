import new_bintrie as t1
import new_bintrie_optimized as t2
import new_bintrie_hex as t3
import new_bintrie_4 as t4
import time
import binascii

keys = [t1.sha3(bytes([i // 256, i % 256])) for i in range(10000)]


def vanilla():
    d = t1.EphemDB()
    r = t1.new_tree(d)
    assert binascii.hexlify(r) == b'a7ff9e28ffd3def443d324547688c2c4eb98edf7da757d6bfa22bff55b9ce24a'
    num_keys = 1000
    a = time.time()
    for k in keys[:num_keys]:
        r = t1.update(d, r, k, k)
    for k in keys[:num_keys]:
        assert t1.get(d, r, k) == k
    print("Naive bintree time to update: %.4f" % (time.time() - a))
    print("Root: %s" % binascii.hexlify(r))
    b = time.time()
    for k in keys[:num_keys]:
        proof = t1.make_merkle_proof(d, r, k)
        assert t1.verify_proof(proof, r, k, k)
    print("Naive bintree time to create and verify %d proofs: %.4f" % (num_keys, time.time() - b))


def vanilla_4():
    d = t4.EphemDB()
    r = t4.new_tree(d)
    assert binascii.hexlify(r) == b'da83700663ba70030c298388bc2fda195ca60bc081326856a469f958c0b41686'
    num_keys = 1000
    a = time.time()
    for k in keys[:num_keys]:
        r = t4.update(d, r, k, k)
    for k in keys[:num_keys]:
        assert t4.get(d, r, k) == k
    print("Width 4 bintree time to update: %.4f" % (time.time() - a))
    print("Root: %s" % binascii.hexlify(r))
    b = time.time()
    for k in keys[:num_keys]:
        proof = t4.make_merkle_proof(d, r, k)
        assert t4.verify_proof(proof, r, k, k)
    print("Width 4 bintree time to create and verify %d proofs: %.4f" % (num_keys, time.time() - b))


def optimized():
    d = t2.EphemDB()
    r = t2.new_tree(d)
    a = time.time()
    num_keys = 3000
    for k in keys[:num_keys]:
        r = t2.update(d, r, k, k)
    print("DB-optimized bintree time to update: %.4f" % (time.time() - a))
    print("Root: %s" % binascii.hexlify(r))
    print("Writes: %d, reads: %d" % (d.writes, d.reads))
    d.reads = 0
    half = num_keys//2
    for k in keys[:half]:
        # assert t2.get(d, r, k) == k
        proof = []
        assert t2.get(d, r, k, proof) == k
        print("proof length is %d" % len(proof))
        print("proof node with len 65 is %s" % [i for i, p in enumerate(proof) if len(p) == 65])
        assert t2.verify_proof(proof, r, k, k)
    for k in keys[-half:]:
        #assert t2.get(d, r, k) == b'\x00' * 32
        proof = []
        assert t2.get(d, r, k, proof) == t2.zero
        assert t2.verify_proof(proof, r, k, t2.zero)
        # print("proof length (-ve) is %d" % len(proof))
    print("Reads: %d" % d.reads)


def optimized_1():
    # Add adjacent leaves
    d = t2.EphemDB()
    r = t2.new_tree(d)
    keys = [0, 1, 2, 3, 6, 100, 101, 102, 1000]
    for k in keys:
        v = (k & t2.tt256m1).to_bytes(32, 'big')
        r = t2._update(d, r, k, 0, v)

    for k in keys:
        v = (k & t2.tt256m1).to_bytes(32, 'big')
        proof = []
        assert t2._get(d, r, k, proof) == v
        assert t2._verify_proof(proof, r, k, v)
        print("proof length is %d" % len(proof))

    for k in [5, 99, 1001]:
        proof = []
        assert t2._get(d, r, k, proof) == t2.zero
        assert t2._verify_proof(proof, r, k, t2.zero)
        print("proof length is %d" % len(proof))

    for k in [7227, 4562, 1085, 1459, 4798, 3645, 1214, 4699, 7700, 3288]:
        v = (k & t2.tt256m1).to_bytes(32, 'big')
        r = t2._update(d, r, k, 0, v)

    for k in [7227, 4562, 1085, 1459, 4798, 3645, 1214, 4699, 7700, 3288]:
        v = (k & t2.tt256m1).to_bytes(32, 'big')
        proof = []
        assert t2._get(d, r, k, proof) == v
        assert t2._verify_proof(proof, r, k, v)

    # for k in keys:
    #     v = (k & t2.tt256m1).to_bytes(32, 'big')
    #     r = t2._update(d, r, k, 0, v)


def hexary():
    d = t3.EphemDB()
    r = t3.new_tree(d)
    a = time.time()
    for k in keys[:1000]:
        r = t3.update(d, r, k, k)
    print("DB-optimized bintree time to update: %.4f" % (time.time() - a))
    print("Root: %s" % binascii.hexlify(r))
    print("Writes: %d, reads: %d" % (d.writes, d.reads))
    d.reads = 0
    for k in keys[:500]:
        assert t3.get(d, r, k) == k
    for k in keys[-500:]:
        assert t3.get(d, r, k) == b'\x00' * 32
    print("Reads: %d" % d.reads)


#vanilla()
#optimized()
#hexary()

#optimized_1()

vanilla_4()
