# Copyright (c) 2020 Raytheon BBN Technologies, Inc.  All Rights Reserved.
# This document does not contain technology or Technical Data controlled under either
# the  U.S. International Traffic in Arms Regulations or the U.S. Export Administration
from ...base import *
from .section import *
class ELFGNUHashSection(StructUnderlay,
                        BaseObject,
                        ELFSection):
    types = frozenset([ 'GNU_HASH' ])
    @classmethod
    def static_init(cls):
        super(ELFGNUHashSection, cls).static_init(config_path='gnu_hash.tsf')
        cls.parse_config()

    def __init__(self, sheader=None, byteorder='little', wordsize=4):
        super().__init__(byteorder=byteorder, wordsize=wordsize)
        self.sheader = sheader
        self.symtab = sheader.parent[sheader.sh_link]
        self.oldbloom = list()
        self.oldbuckets = list()
        self.oldchains = list()
        self.bloom = list()
        self.buckets = list()
        self.chains = list()

    def from_bytes(self, data):
        super().from_bytes(data)
        size = self.sheader.sh_size
        offset = 4 * 4
        self.oldsymoffset = self.symoffset
        for i in range(0, self.bloomsize):
            self.oldbloom.append(int.from_bytes(data[offset:offset+8], byteorder=self.byteorder))
            offset += 8
        for i in range(0, self.nbuckets):
            self.oldbuckets.append(int.from_bytes(data[offset:offset+4], byteorder=self.byteorder))
            offset += 4
        while offset < size:
            self.oldchains.append(int.from_bytes(data[offset:offset+4], byteorder=self.byteorder))
            offset += 4

    def validate(self):
        temp_symoffset = self.symoffset
        temp_bloom = self.bloom
        temp_buckets = self.buckets
        temp_chains = self.chains

        self.symoffset = self.oldsymoffset
        self.bloom = self.oldbloom
        self.buckets = self.oldbuckets
        self.chains = self.oldchains

        if not self.verify():
            return False

        self.bloom = temp_bloom
        self.buckets = temp_buckets
        self.chains = temp_chains

        return True

    def verify(self, *args):
        out = True

        # Check basic metadata integrity.
        if len(self.bloom) != self.bloomsize:
            self.l.error("Expected {:d} bloom filter entries, but found {:d}".format(self.bloomsize, len(self.bloom)))
            out = False
        if len(self.buckets) != self.nbuckets:
            self.l.error("Expected {:d} buckets, but found {:d}".format(self.nbuckets, len(self.buckets)))
            out = False
        if len(self.chains) != (len(self.symtab.section) - self.symoffset):
            self.l.error("Expected {:d} chain entries, but found {:d}".format(len(self.symtab.section) - self.symoffset, len(self.chains)))
            out = False

        seen_chain_idxs = dict()
        seen_names = dict()

        for symbol in self.symtab.section.items[self.symoffset:]:

            # Check symbol table integrity.
            name = '{!s}'.format(symbol)
            if name in seen_names:
                self.l.error('Symbol {:d} ({:s}) was already entered as symbol {:d}'.format(symbol.idx, name, seen_names[name]))
                out = False
            else:
                seen_names[name] = symbol.idx

            hsh = self.gnu_hash(symbol)
            bloom_idx = self.gnu_bloom_idx(symbol)
            (bloom_a, bloom_b) = self.gnu_bloom_bits(symbol)
            bucket_idx = self.gnu_bucket_idx(symbol)
            

            # Check bloom filter.
            bloom_elem = self.bloom[bloom_idx]
            if bloom_elem & (1 << bloom_a) == 0:
                self.l.error("Missing unshifted bloom filter bit for symbol {:d} ({!s}): ({:d}, {:d}) => {:x}".format(symbol.idx, symbol, bloom_idx, bloom_a, bloom_elem))
                out = False
            if bloom_elem & (1 << bloom_b) == 0:
                self.l.error("Missing shifted bloom filter bit for symbol {:d} ({!s}): ({:d}, {:d}) => {:x}".format(symbol.idx, symbol, bloom_idx, bloom_b, bloom_elem))
                out = False

            # Check bucket
            chain_idx = self.buckets[bucket_idx]
            if chain_idx == 0:
                self.l.error("Bucket for symbol {:d} ({!s}) - {:d} - is zero; symbol isn't present.".format(symbol.idx, symbol, bucket_idx))
                out = False
            chain_idx = chain_idx - self.symoffset
            if chain_idx >= len(self.chains):
                self.l.error("Bucket for symbol {:d} ({!s}) is outside the bounds of the chains: Expected {:d} but found {:d} ({:x})".format(symbol.idx, symbol, len(self.chains), chain_idx, chain_idx))

            # Check chain
            good = False
            while True:
                if chain_idx >= len(self.chains):
                    break
                if self.chains[chain_idx] & 0xFFFFFFFE == self.gnu_chain_entry(symbol):
                    good = True
                    break
                elif self.chains[chain_idx] & 1 != 0:
                    break
                chain_idx += 1

            if not good:
                # We missed the symbol entirely.
                self.l.error("Could not find a hash match for symbol {:d} ({!s}) between {:d} and {:d}".format(symbol.idx, symbol, self.buckets[bucket_idx] - self.symoffset, chain_idx))
                out = False

            elif self.symtab.section.items[self.symoffset + chain_idx].get_referenced_object('st_name') != symbol.get_referenced_object('st_name'):
                # Check that we actually found the correct symbol.
                self.l.error("Hash match produced false results: Expected {!s} but got {!s}".format(symbol, self.symtab.section.items[self.symoffset + chain_idx]))
                out = False

            elif self.symoffset + chain_idx != symbol.idx:
                # Check that we found the same entry in the symbol table.
                self.l.error('Symbol names matched, but indexes did not; expected {:d} but computed {:d} for {!s}'.format(self.symoffset + chain_idx, symbol.idx, symbol))
                out = False

            elif chain_idx in seen_chain_idxs:
                # Check if we're seeing double.
                self.l.error("Hash matched produced duplicate results; symbol {:d} ({!s}) was already in the table as {!s}".format(symbol.idx, symbol, seen_chain_idxs[chain_idx]))
                out = False

            else:
                seen_chain_idxs[chain_idx] = symbol

            if not good:
                chain_idx = 0
                while True:
                    if chain_idx >= len(self.chains):
                        self.l.error('Symbol {:d} ({!s}) is nowhere in the hash table; check your hash {:x}'.format(symbol.idx, symbol, self.gnu_hash(symbol)))
                        break;
                    elif self.chains[chain_idx] & 0xFFFFFFFE == self.gnu_chain_entry(symbol):
                        self.l.error('Symbol {:d} ({!s}) had a hash match at idx {:d}, outside its expected bucket.'.format(symbol.idx, symbol, chain_idx))
                        break;
                    chain_idx += 1


        return out


    def organize(self, *args):
        self.bloom = [ 0 ] * self.bloomsize
        self.buckets = [ 0 ] * self.nbuckets

        relevant_syms = list(filter(self.gnu_need_hash, self.symtab.section.items))
        irrelevant_syms = list(filter(lambda x: not self.gnu_need_hash(x), self.symtab.section.items))

        relevant_syms.sort(key=self.gnu_hash)
        relevant_syms.sort(key=self.gnu_bucket_idx)

        self.symoffset = len(irrelevant_syms)
        self.symtab.section.items = irrelevant_syms + relevant_syms
        self.symtab.section.clean()
        
        self.chains = list(map(self.gnu_chain_entry, relevant_syms))

        bucket_list = list(map(self.gnu_bucket_idx, relevant_syms))
        bloom_idx_list = list(map(self.gnu_bloom_idx, relevant_syms))
        bloom_bit_list = list(map(self.gnu_bloom_bits, relevant_syms))

        last_bucket = -1
        for i in range(0, len(bucket_list)):
            # Update the buckets
            if bucket_list[i] != last_bucket:
                last_bucket = bucket_list[i]
                self.buckets[last_bucket] = i + self.symoffset
                # Mark end-of-chain elements.
                if i > 0:
                    self.chains[i - 1] = self.chains[i - 1] | 1
            # Update the bloom filter
            bloom_idx = bloom_idx_list[i]
            (bloom_a, bloom_b) = bloom_bit_list[i]
            self.bloom[bloom_idx] |= (1 << bloom_a) | (1 << bloom_b)
        # Mark the final end of chain element
        if len(self.chains) > 0:
            self.chains[-1] = self.chains[-1] | 1


    def pprint(self, am_organized=False):
        super().pprint()
        if not am_organized:
            self.organize()
        print("\tBloom Filters: {!s}".format(list(map(lambda x: '{:x}'.format(x), self.bloom))))
        print("\tBuckets:")
        for i in range(0, self.nbuckets):
            print("\t\t{:d}: {:d}".format(i, self.buckets[i]))
        print("\tChains:")
        for i in range(0, len(self.chains)):
            print("\t\t{:d}: {:x}".format(i, self.chains[i]))

    def to_bytes(self, write):
        out = super().to_bytes(write)

        for b in self.bloom:
            write(b.to_bytes(self.wordsize, byteorder=self.byteorder))
            out += self.wordsize
        for b in self.buckets:
            write(b.to_bytes(4, byteorder=self.byteorder))
            out += 4
        for c in self.chains:
            write(c.to_bytes(4, byteorder=self.byteorder))
            out += 4
        return out

    @property
    def size(self):
        out = 16
        out += self.bloomsize * self.wordsize
        out += self.nbuckets * 4
        out += len(self.chains) * 4
        return out

    def gnu_need_hash(self, symbol):
        #TODO: I think this is more complicated, but whatevs.
        return symbol.st_shndx != 0x00

    def gnu_hash(self, symbol):
        out = 5381
        for c in symbol.get_referenced_object('st_name'):
            if c == 0:
                break
            out = (out << 5) + out + c
            out &= 0xFFFFFFFF
        return out

    def gnu_bucket_idx(self, symbol):
        return self.gnu_hash(symbol) % self.nbuckets

    def gnu_chain_entry(self, symbol):
        mask = (1 << 64) - 2
        return self.gnu_hash(symbol) & mask

    def gnu_bloom_idx(self, symbol):
        wordbits = self.wordsize * 8
        return (self.gnu_hash(symbol) // wordbits) % self.bloomsize

    def gnu_bloom_bits(self, symbol):
        wordbits = self.wordsize * 8
        hsh = self.gnu_hash(symbol)
        unshift = hsh % wordbits
        shift = (hsh >> self.bloomshift) % wordbits
        return (unshift, shift)

ELFGNUHashSection.static_init()


