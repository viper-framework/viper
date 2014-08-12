#
#    peepdf is a tool to analyse and modify PDF files
#    http://peepdf.eternal-todo.com
#    By Jose Miguel Esparza <jesparza AT eternal-todo.com>
#
#    Copyright (C) 2012-2014 Jose Miguel Esparza
#
#    This file is part of peepdf.
#
#        peepdf is free software: you can redistribute it and/or modify
#        it under the terms of the GNU General Public License as published by
#        the Free Software Foundation, either version 3 of the License, or
#        (at your option) any later version.
#
#        peepdf is distributed in the hope that it will be useful,
#        but WITHOUT ANY WARRANTY; without even the implied warranty of
#        MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.    See the
#        GNU General Public License for more details.
#
#        You should have received a copy of the GNU General Public License
#        along with peepdf.    If not, see <http://www.gnu.org/licenses/>.
#

'''
    Library to encode/decode streams using the LZW algorithm. Mix of third party libraries (python-lzw and pdfminer) with some modifications.
'''

"""
A stream friendly, simple compression library, built around
iterators. See L{compress} and L{decompress} for the easiest way to
get started.

After the TIFF implementation of LZW, as described at
U{http://www.fileformat.info/format/tiff/corion-lzw.htm}


In an even-nuttier-shell, lzw compresses input bytes with integer
codes. Starting with codes 0-255 that code to themselves, and two
control codes, we work our way through a stream of bytes. When we
encounter a pair of codes c1,c2 we add another entry to our code table
with the lowest available code and the value value(c1) + value(c2)[0]

Of course, there are details :)

The Details
===========

    Our control codes are

        - CLEAR_CODE (codepoint 256). When this code is encountered, we flush
          the codebook and start over.
        - END_OF_INFO_CODE (codepoint 257). This code is reserved for
          encoder/decoders over the integer codepoint stream (like the
          mechanical bit that unpacks bits into codepoints)

    When dealing with bytes, codes are emitted as variable
    length bit strings packed into the stream of bytes.

    codepoints are written with varying length
        - initially 9 bits
        - at 512 entries 10 bits
        - at 1025 entries at 11 bits
        - at 2048 entries 12 bits
        - with max of 4095 entries in a table (including Clear and EOI)

    code points are stored with their MSB in the most significant bit
    available in the output character.

>>> import lzw
>>>
>>> mybytes = lzw.readbytes("README.txt")
>>> lessbytes = lzw.compress(mybytes)
>>> newbytes = b"".join(lzw.decompress(lessbytes))
>>> oldbytes = b"".join(lzw.readbytes("README.txt"))
>>> oldbytes == newbytes
True

__author__ = "Joe Bowers"
__license__ = "MIT License"
__version__ = "0.01.01"
__status__ = "Development"
__email__ = "joerbowers@gmail.com"
__url__ = "http://www.joe-bowers.com/static/lzw"

"""


import struct
import itertools


CLEAR_CODE = 256
END_OF_INFO_CODE = 257

DEFAULT_MIN_BITS = 9
DEFAULT_MAX_BITS = 12




def compress(plaintext_bytes):
    """
    Given an iterable of bytes, returns a (hopefully shorter) iterable
    of bytes that you can store in a file or pass over the network or
    what-have-you, and later use to get back your original bytes with
    L{decompress}. This is the best place to start using this module.
    """
    encoder = ByteEncoder()
    return encoder.encodetobytes(plaintext_bytes)


def decompress(compressed_bytes):
    """
    Given an iterable of bytes that were the result of a call to
    L{compress}, returns an iterator over the uncompressed bytes.
    """
    decoder = ByteDecoder()
    return decoder.decodefrombytes(compressed_bytes)





class ByteEncoder(object):
    """
    Takes a stream of uncompressed bytes and produces a stream of
    compressed bytes, usable by L{ByteDecoder}. Combines an L{Encoder}
    with a L{BitPacker}.


    >>> import lzw
    >>>
    >>> enc = lzw.ByteEncoder(12)
    >>> bigstr = b"gabba gabba yo gabba gabba gabba yo gabba gabba gabba yo gabba gabba gabba yo"
    >>> encoding = enc.encodetobytes(bigstr)
    >>> encoded = b"".join( b for b in encoding )
    >>> encoded
    '3\\x98LF#\\x08\\x82\\x05\\x04\\x83\\x1eM\\xf0x\\x1c\\x16\\x1b\\t\\x88C\\xe1q(4"\\x1f\\x17\\x85C#1X\\xec.\\x00'
    >>>
    >>> dec = lzw.ByteDecoder()
    >>> decoding = dec.decodefrombytes(encoded)
    >>> decoded = b"".join(decoding)
    >>> decoded == bigstr
    True

    """

    def __init__(self, max_width=DEFAULT_MAX_BITS):
       """
       max_width is the maximum width in bits we want to see in the
       output stream of codepoints.
       """
       self._encoder = Encoder(max_code_size=2**max_width)
       self._packer = BitPacker(initial_code_size=self._encoder.code_size())


    def encodetobytes(self, bytesource):
        """
        Returns an iterator of bytes, adjusting our packed width
        between minwidth and maxwidth when it detects an overflow is
        about to occur. Dual of L{ByteDecoder.decodefrombytes}.
        """
        codepoints = self._encoder.encode(bytesource)
        codebytes = self._packer.pack(codepoints)

        return codebytes


class ByteDecoder(object):
    """
    Decodes, combines bit-unpacking and interpreting a codepoint
    stream, suitable for use with bytes generated by
    L{ByteEncoder}.

    See L{ByteDecoder} for a usage example.
    """
    def __init__(self):
       """
       """

       self._decoder = Decoder()
       self._unpacker = BitUnpacker(initial_code_size=self._decoder.code_size())
       self.remaining = []

    def decodefrombytes(self, bytesource):
       """
       Given an iterator over BitPacked, Encoded bytes, Returns an
       iterator over the uncompressed bytes. Dual of
       L{ByteEncoder.encodetobytes}. See L{ByteEncoder} for an
       example of use.
       """        
       codepoints = self._unpacker.unpack(bytesource)
       clearbytes = self._decoder.decode(codepoints)
       
       return clearbytes


class BitPacker(object):
    """
    Translates a stream of lzw codepoints into a variable width packed
    stream of bytes, for use by L{BitUnpacker}.  One of a (potential)
    set of encoders for a stream of LZW codepoints, intended to behave
    as closely to the TIFF variable-width encoding scheme as closely
    as possible.

    The inbound stream of integer lzw codepoints are packed into
    variable width bit fields, starting at the smallest number of bits
    it can and then increasing the bit width as it anticipates the LZW
    code size growing to overflow.

    This class knows all kinds of intimate things about how it's
    upstream codepoint processors work; it knows the control codes
    CLEAR_CODE and END_OF_INFO_CODE, and (more intimately still), it
    makes assumptions about the rate of growth of it's consumer's
    codebook. This is ok, as long as the underlying encoder/decoders
    don't know any intimate details about their BitPackers/Unpackers
    """

    def __init__(self, initial_code_size):
       """
       Takes an initial code book size (that is, the count of known
       codes at the beginning of encoding, or after a clear)
       """
       self._initial_code_size = initial_code_size


    def pack(self, codepoints):
        """
        Given an iterator of integer codepoints, returns an iterator
        over bytes containing the codepoints packed into varying
        lengths, with bit width growing to accomodate an input code
        that it assumes will grow by one entry per codepoint seen.

        Widths will be reset to the given initial_code_size when the
        LZW CLEAR_CODE or END_OF_INFO_CODE code appears in the input,
        and bytes following END_OF_INFO_CODE will be aligned to the
        next byte boundary.

        >>> import lzw
        >>> pkr = lzw.BitPacker(258)
        >>> [ b for b in pkr.pack([ 1, 257]) ] == [ chr(0), chr(0xC0), chr(0x40) ]
        True
        """
        tailbits = []
        codesize = self._initial_code_size

        minwidth = 8
        while (1 << minwidth) < codesize:
            minwidth = minwidth + 1

        nextwidth = minwidth

        for pt in codepoints:

            newbits = inttobits(pt, nextwidth)
            tailbits = tailbits + newbits

            # PAY ATTENTION. This calculation should be driven by the
            # size of the upstream codebook, right now we're just trusting
            # that everybody intends to follow the TIFF spec.
            codesize = codesize + 1
            if pt == END_OF_INFO_CODE:
               while len(tailbits) % 8:
                  tailbits.append(0)
                  
            if pt in [ CLEAR_CODE, END_OF_INFO_CODE ]:
                nextwidth = minwidth
                codesize = self._initial_code_size
            elif codesize >= (2 ** nextwidth):
                nextwidth = nextwidth + 1

            while len(tailbits) > 8:
                nextbits = tailbits[:8]
                nextbytes = bitstobytes(nextbits)
                for bt in nextbytes:
                    yield struct.pack("B", bt)

                tailbits = tailbits[8:]

                       
        if tailbits:
            tail = bitstobytes(tailbits)
            for bt in tail:
                yield struct.pack("B", bt)

                


class BitUnpacker(object):
    """
    An adaptive-width bit unpacker, intended to decode streams written
    by L{BitPacker} into integer codepoints. Like L{BitPacker}, knows
    about code size changes and control codes.
    """

    def __init__(self, initial_code_size):
       """
       initial_code_size is the starting size of the codebook
       associated with the to-be-unpacked stream.
       """
       self._initial_code_size = initial_code_size


    def unpack(self, bytesource):
        """
        Given an iterator of bytes, returns an iterator of integer
        code points. Auto-magically adjusts point width when it sees
        an almost-overflow in the input stream, or an LZW CLEAR_CODE
        or END_OF_INFO_CODE

        Trailing bits at the end of the given iterator, after the last
        codepoint, will be dropped on the floor.

        At the end of the iteration, or when an END_OF_INFO_CODE seen
        the unpacker will ignore the bits after the code until it
        reaches the next aligned byte. END_OF_INFO_CODE will *not*
        stop the generator, just reset the alignment and the width


        >>> import lzw
        >>> unpk = lzw.BitUnpacker(initial_code_size=258)
        >>> [ i for i in unpk.unpack([ chr(0), chr(0xC0), chr(0x40) ]) ]
        [1, 257]
        """
        bits = []
        offset = 0
        ignore = 0
        
        codesize = self._initial_code_size
        minwidth = 8
        while (1 << minwidth) < codesize:
            minwidth = minwidth + 1

        pointwidth = minwidth

        for nextbit in bytestobits(bytesource):

            offset = (offset + 1) % 8
            if ignore > 0:
                ignore = ignore - 1
                continue

            bits.append(nextbit)

            if len(bits) == pointwidth:
                codepoint = intfrombits(bits)
                bits = []

                yield codepoint

                codesize = codesize + 1

                if codepoint in [ CLEAR_CODE, END_OF_INFO_CODE ]:
                    codesize = self._initial_code_size
                    pointwidth = minwidth
                else:
                    # is this too late?
                    while codesize >= (2 ** pointwidth):
                        pointwidth = pointwidth + 1

                if codepoint == END_OF_INFO_CODE:
                    ignore = (8 - offset) % 8



class Decoder(object):
    """
    Uncompresses a stream of lzw code points, as created by
    L{Encoder}. Given a list of integer code points, with all
    unpacking foolishness complete, turns that list of codepoints into
    a list of uncompressed bytes. See L{BitUnpacker} for what this
    doesn't do.
    """
    def __init__(self):
       """
       Creates a new Decoder. Decoders should not be reused for
       different streams.
       """
       self._clear_codes()
       self.remainder = []


    def code_size(self):
       """
       Returns the current size of the Decoder's code book, that is,
       it's mapping of codepoints to byte strings. The return value of
       this method will change as the decode encounters more encoded
       input, or control codes.
       """
       return len(self._codepoints)


    def decode(self, codepoints):
        """
        Given an iterable of integer codepoints, yields the
        corresponding bytes, one at a time, as byte strings of length
        E{1}. Retains the state of the codebook from call to call, so
        if you have another stream, you'll likely need another
        decoder!

        Decoders will NOT handle END_OF_INFO_CODE (rather, they will
        handle the code by throwing an exception); END_OF_INFO should
        be handled by the upstream codepoint generator (see
        L{BitUnpacker}, for example)

        >>> import lzw
        >>> dec = lzw.Decoder()
        >>> ''.join(dec.decode([103, 97, 98, 98, 97, 32, 258, 260, 262, 121, 111, 263, 259, 261, 256]))
        'gabba gabba yo gabba'

        """
        codepoints = [ cp for cp in codepoints ]

        for cp in codepoints:
            decoded = self._decode_codepoint(cp)
            for character in decoded:
                yield character



    def _decode_codepoint(self, codepoint):
        """
        Will raise a ValueError if given an END_OF_INFORMATION
        code. EOI codes should be handled by callers if they're
        present in our source stream.

        >>> import lzw
        >>> dec = lzw.Decoder()
        >>> beforesize = dec.code_size()
        >>> dec._decode_codepoint(0x80)
        '\\x80'
        >>> dec._decode_codepoint(0x81)
        '\\x81'
        >>> beforesize + 1 == dec.code_size()
        True
        >>> dec._decode_codepoint(256)
        ''
        >>> beforesize == dec.code_size()
        True
        """

        ret = ""

        if codepoint == CLEAR_CODE:
            self._clear_codes()
        elif codepoint == END_OF_INFO_CODE:
            pass
            #raise ValueError("End of information code not supported directly by this Decoder")
        else:
            if codepoint in self._codepoints:
                ret = self._codepoints[ codepoint ]
                if None != self._prefix:
                    self._codepoints[ len(self._codepoints) ] = self._prefix + ret[0]

            else:
                ret = self._prefix + self._prefix[0]
                self._codepoints[ len(self._codepoints) ] = ret

            self._prefix = ret

        return ret


    def _clear_codes(self):
        self._codepoints = dict( (pt, struct.pack("B", pt)) for pt in range(256) )
        self._codepoints[CLEAR_CODE] = CLEAR_CODE
        self._codepoints[END_OF_INFO_CODE] = END_OF_INFO_CODE
        self._prefix = None


class Encoder(object):
    """
    Given an iterator of bytes, returns an iterator of integer
    codepoints, suitable for use by L{Decoder}. The core of the
    "compression" side of lzw compression/decompression.
    """
    def __init__(self, max_code_size=(2**DEFAULT_MAX_BITS)):
        """
        When the encoding codebook grows larger than max_code_size,
        the Encoder will clear its codebook and emit a CLEAR_CODE
        """

        self.closed = False

        self._max_code_size = max_code_size
        self._buffer = ''
        self._clear_codes()            

        if max_code_size < self.code_size():
            raise ValueError("Max code size too small, (must be at least {0})".format(self.code_size()))


    def code_size(self):
        """
        Returns a count of the known codes, including codes that are
        implicit in the data but have not yet been produced by the
        iterator.
        """
        return len(self._prefixes)


    def flush(self):
        """
        Yields any buffered codepoints, followed by a CLEAR_CODE, and
        clears the codebook as a side effect.
        """

        flushed = []

        if self._buffer:
            yield self._prefixes[ self._buffer ]
            self._buffer = ''            

        yield CLEAR_CODE
        self._clear_codes()

            


    def encode(self, bytesource):
        """
        Given an iterator over bytes, yields the
        corresponding stream of codepoints.
        Will clear the codes at the end of the stream.

        >>> import lzw
        >>> enc = lzw.Encoder()
        >>> [ cp for cp in enc.encode("gabba gabba yo gabba") ]
        [103, 97, 98, 98, 97, 32, 258, 260, 262, 121, 111, 263, 259, 261, 256]
        
        Modified by Jose Miguel Esparza to add support for PDF files encoding
        """
        yield CLEAR_CODE
        for b in bytesource:
            for point in self._encode_byte(b):
                yield point

            if self.code_size() >= self._max_code_size:
                for pt in self.flush():
                    yield pt

        yield self._prefixes[self._buffer]
        yield END_OF_INFO_CODE


    def _encode_byte(self, byte):
        # Yields one or zero bytes, AND changes the internal state of
        # the codebook and prefix buffer.
        #
        # Unless you're in self.encode(), you almost certainly don't
        # want to call this.

        new_prefix = self._buffer
        
        if new_prefix + byte in self._prefixes:
            new_prefix = new_prefix + byte
        elif new_prefix:
            encoded = self._prefixes[ new_prefix ]
            self._add_code(new_prefix + byte)
            new_prefix = byte

            yield encoded
        
        self._buffer = new_prefix




    def _clear_codes(self):

        # Teensy hack, CLEAR_CODE and END_OF_INFO_CODE aren't
        # equal to any possible string.

        self._prefixes = dict( (struct.pack("B", codept), codept) for codept in range(256) )
        self._prefixes[ CLEAR_CODE ] = CLEAR_CODE
        self._prefixes[ END_OF_INFO_CODE ] = END_OF_INFO_CODE


    def _add_code(self, newstring):
        self._prefixes[ newstring ] = len(self._prefixes)



class PagingEncoder(object):
    """
    UNTESTED. Handles encoding of multiple chunks or streams of encodable data,
    separated with control codes. Dual of PagingDecoder.
    """
    def __init__(self, initial_code_size, max_code_size):
        self._initial_code_size = initial_code_size
        self._max_code_size = max_code_size


    def encodepages(self, pages):
        """
        Given an iterator of iterators of bytes, produces a single
        iterator containing a delimited sequence of independantly
        compressed LZW sequences, all beginning on a byte-aligned
        spot, all beginning with a CLEAR code and all terminated with
        an END_OF_INFORMATION code (and zero to seven trailing junk
        bits.)

        The dual of PagingDecoder.decodepages

        >>> import lzw
        >>> enc = lzw.PagingEncoder(257, 2**12)
        >>> coded = enc.encodepages([ "say hammer yo hammer mc hammer go hammer", 
        ...                           "and the rest can go and play",
        ...                           "can't touch this" ])
        ...
        >>> b"".join(coded)
        '\\x80\\x1c\\xcc\\'\\x91\\x01\\xa0\\xc2m6\\x99NB\\x03\\xc9\\xbe\\x0b\\x07\\x84\\xc2\\xcd\\xa68|"\\x14 3\\xc3\\xa0\\xd1c\\x94\\x02\\x02\\x80\\x18M\\xc6A\\x01\\xd0\\xd0e\\x10\\x1c\\x8c\\xa73\\xa0\\x80\\xc7\\x02\\x10\\x19\\xcd\\xe2\\x08\\x14\\x10\\xe0l0\\x9e`\\x10\\x10\\x80\\x18\\xcc&\\xe19\\xd0@t7\\x9dLf\\x889\\xa0\\xd2s\\x80@@'

        """

        for page in pages:

            encoder = Encoder(max_code_size=self._max_code_size)
            codepoints = encoder.encode(page)
            codes_and_eoi = itertools.chain([ CLEAR_CODE ], codepoints, [ END_OF_INFO_CODE ])

            packer = BitPacker(initial_code_size=encoder.code_size())
            packed = packer.pack(codes_and_eoi)

            for byte in packed: 
                yield byte


            

class PagingDecoder(object):
    """
    UNTESTED. Dual of PagingEncoder, knows how to handle independantly encoded,
    END_OF_INFO_CODE delimited chunks of an inbound byte stream
    """

    def __init__(self, initial_code_size):
        self._initial_code_size = initial_code_size
        self._remains = []

    def next_page(self, codepoints):
        """
        Iterator over the next page of codepoints.
        """
        self._remains = []

        try:
            while 1:
                cp = codepoints.next()
                if cp != END_OF_INFO_CODE:
                    yield cp
                else:
                    self._remains = codepoints
                    break

        except StopIteration:
            pass
        

    def decodepages(self, bytesource):
        """
        Takes an iterator of bytes, returns an iterator of iterators
        of uncompressed data. Expects input to conform to the output
        conventions of PagingEncoder(), in particular that "pages" are
        separated with an END_OF_INFO_CODE and padding up to the next
        byte boundary.

        BUG: Dangling trailing page on decompression.

        >>> import lzw
        >>> pgdec = lzw.PagingDecoder(initial_code_size=257)
        >>> pgdecoded = pgdec.decodepages(
        ...     ''.join([ '\\x80\\x1c\\xcc\\'\\x91\\x01\\xa0\\xc2m6',
        ...               '\\x99NB\\x03\\xc9\\xbe\\x0b\\x07\\x84\\xc2',
        ...               '\\xcd\\xa68|"\\x14 3\\xc3\\xa0\\xd1c\\x94',
        ...               '\\x02\\x02\\x80\\x18M\\xc6A\\x01\\xd0\\xd0e',
        ...               '\\x10\\x1c\\x8c\\xa73\\xa0\\x80\\xc7\\x02\\x10',
        ...               '\\x19\\xcd\\xe2\\x08\\x14\\x10\\xe0l0\\x9e`\\x10',
        ...               '\\x10\\x80\\x18\\xcc&\\xe19\\xd0@t7\\x9dLf\\x889',
        ...               '\\xa0\\xd2s\\x80@@' ])
        ... )
        >>> [ b"".join(pg) for pg in pgdecoded ]
        ['say hammer yo hammer mc hammer go hammer', 'and the rest can go and play', "can't touch this", '']

        """

        # TODO: WE NEED A CODE SIZE POLICY OBJECT THAT ISN'T THIS.
        # honestly, we should have a "codebook" object we need to pass
        # to bit packing/unpacking tools, etc, such that we don't have
        # to roll all of these code size assumptions everyplace.

        unpacker = BitUnpacker(initial_code_size=self._initial_code_size)
        codepoints = unpacker.unpack(bytesource)

        self._remains = codepoints
        while self._remains:
            nextpoints = self.next_page(self._remains)
            nextpoints = [ nx for nx in nextpoints ]

            decoder = Decoder()
            decoded = decoder.decode(nextpoints)
            decoded = [ dec for dec in decoded ]

            yield decoded



#########################################
# Conveniences.


# PYTHON V2
def unpackbyte(b):
   """
   Given a one-byte long byte string, returns an integer. Equivalent
   to struct.unpack("B", b)
   """
   (ret,) = struct.unpack("B", b)
   return ret


# PYTHON V3
# def unpackbyte(b): return b


def filebytes(fileobj, buffersize=1024):
    """
    Convenience for iterating over the bytes in a file. Given a
    file-like object (with a read(int) method), returns an iterator
    over the bytes of that file.
    """
    buff = fileobj.read(buffersize)
    while buff:
        for byte in buff: yield byte
        buff = fileobj.read(buffersize)

    
def readbytes(filename, buffersize=1024):
    """
    Opens a file named by filename and iterates over the L{filebytes}
    found therein.  Will close the file when the bytes run out.
    """
    infile = open(filename, "rb")
    for byte in filebytes(infile, buffersize):
        yield byte



def writebytes(filename, bytesource):
    """
    Convenience for emitting the bytes we generate to a file. Given a
    filename, opens and truncates the file, dumps the bytes
    from bytesource into it, and closes it
    """

    outfile = open(filename, "wb")
    for bt in bytesource:
        outfile.write(bt)


def inttobits(anint, width=None):
    """
    Produces an array of booleans representing the given argument as
    an unsigned integer, MSB first. If width is given, will pad the
    MSBs to the given width (but will NOT truncate overflowing
    results)

    >>> import lzw
    >>> lzw.inttobits(304, width=16)
    [0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 1, 1, 0, 0, 0, 0]

    """
    remains = anint
    retreverse = []
    while remains:
        retreverse.append(remains & 1)
        remains = remains >> 1

    retreverse.reverse()

    ret = retreverse
    if None != width:
        ret_head = [ 0 ] * (width - len(ret))
        ret = ret_head + ret

    return ret


def intfrombits(bits):
    """
    Given a list of boolean values, interprets them as a binary
    encoded, MSB-first unsigned integer (with True == 1 and False
    == 0) and returns the result.
    
    >>> import lzw
    >>> lzw.intfrombits([ 1, 0, 0, 1, 1, 0, 0, 0, 0 ])
    304
    """
    ret = 0
    lsb_first = [ b for b in bits ]
    lsb_first.reverse()
    
    for bit_index in range(len(lsb_first)):
        if lsb_first[ bit_index ]:
            ret = ret | (1 << bit_index)

    return ret


def bytestobits(bytesource):
    """
    Breaks a given iterable of bytes into an iterable of boolean
    values representing those bytes as unsigned integers.
    
    >>> import lzw
    >>> [ x for x in lzw.bytestobits(b"\\x01\\x30") ]
    [0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 1, 1, 0, 0, 0, 0]
    """
    for b in bytesource:

        value = unpackbyte(b)

        for bitplusone in range(8, 0, -1):
            bitindex = bitplusone - 1
            nextbit = 1 & (value >> bitindex)
            yield nextbit


def bitstobytes(bits):
    """
    Interprets an indexable list of booleans as bits, MSB first, to be
    packed into a list of integers from 0 to 256, MSB first, with LSBs
    zero-padded. Note this padding behavior means that round-trips of
    bytestobits(bitstobytes(x, width=W)) may not yield what you expect
    them to if W % 8 != 0

    Does *NOT* pack the returned values into a bytearray or the like.

    >>> import lzw
    >>> bitstobytes([0, 0, 0, 0, 0, 0, 0, 0, "Yes, I'm True"]) == [ 0x00, 0x80 ]
    True
    >>> bitstobytes([0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 1, 1, 0, 0, 0, 0]) == [ 0x01, 0x30 ]
    True
    """
    ret = []
    nextbyte = 0
    nextbit = 7
    for bit in bits:
        if bit:
            nextbyte = nextbyte | (1 << nextbit)

        if nextbit:
            nextbit = nextbit - 1
        else:
            ret.append(nextbyte)
            nextbit = 7
            nextbyte = 0

    if nextbit < 7: ret.append(nextbyte)
    return ret
        



'''
The code below is part of pdfminer (http://pypi.python.org/pypi/pdfminer/)

Copyright (c) 2004-2010 Yusuke Shinyama <yusuke at cs dot nyu dot edu>

Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files (the "Software"), to deal in the Software without restriction, including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, and to permit persons to whom the Software is furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE. 
'''

import sys
try:
    from cStringIO import StringIO
except ImportError:
    from StringIO import StringIO


##  LZWDecoder
##
class LZWDecoder(object):

    debug = 0

    def __init__(self, fp):
        self.fp = fp
        self.buff = 0
        self.bpos = 8
        self.nbits = 9
        self.table = None
        self.prevbuf = None
        return

    def readbits(self, bits):
        v = 0
        while 1:
            # the number of remaining bits we can get from the current buffer.
            r = 8-self.bpos
            if bits <= r:
                # |-----8-bits-----|
                # |-bpos-|-bits-|  |
                # |      |----r----|
                v = (v<<bits) | ((self.buff>>(r-bits)) & ((1<<bits)-1))
                self.bpos += bits
                break
            else:
                # |-----8-bits-----|
                # |-bpos-|---bits----...
                # |      |----r----|
                v = (v<<r) | (self.buff & ((1<<r)-1))
                bits -= r
                x = self.fp.read(1)
                if not x: raise EOFError
                self.buff = ord(x)
                self.bpos = 0
        return v

    def feed(self, code):
        x = ''
        if code == 256:
            self.table = [ chr(c) for c in xrange(256) ] # 0-255
            self.table.append(None) # 256
            self.table.append(None) # 257
            self.prevbuf = ''
            self.nbits = 9
        elif code == 257:
            pass
        elif not self.prevbuf:
            x = self.prevbuf = self.table[code]
        else:
            if code < len(self.table):
                x = self.table[code]
                self.table.append(self.prevbuf+x[0])
            else:
                self.table.append(self.prevbuf+self.prevbuf[0])
                x = self.table[code]
            l = len(self.table)
            if l == 511:
                self.nbits = 10
            elif l == 1023:
                self.nbits = 11
            elif l == 2047:
                self.nbits = 12
            self.prevbuf = x
        return x

    def run(self):
        while 1:
            try:
                code = self.readbits(self.nbits)
            except EOFError:
                break
            x = self.feed(code)
            yield x
            if self.debug:
                print >>sys.stderr, ('nbits=%d, code=%d, output=%r, table=%r' %
                                     (self.nbits, code, x, self.table[258:]))
        return


def lzwdecode(data):
    """
    >>> lzwdecode('\x80\x0b\x60\x50\x22\x0c\x0c\x85\x01')
    '\x2d\x2d\x2d\x2d\x2d\x41\x2d\x2d\x2d\x42'
    """
    fp = StringIO(data)
    return ''.join(LZWDecoder(fp).run())