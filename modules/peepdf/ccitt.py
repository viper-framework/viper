#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""
ccitt.py

TODO
http://tools.ietf.org/pdf/rfc804.pdf
http://code.google.com/p/origami-pdf/source/browse/lib/origami/filters/ccitt.rb
"""
__author__  = 'Binjo'
__version__ = '0.1'
__date__    = '2012-04-08 14:30:05'

class BitWriterException(Exception):
    pass

class BitWriter(object):
    """
    """

    def __init__(self, ):
        """
        """
        self._data = ''
        self._last_byte = None
        self._bit_ptr = 0

    @property
    def data(self):
        """
        """
        return self._data

    def write(self, data, length):
        """
        """
        if not ( length >= 0 and (1 << length) > data ):
            raise BitWriterException, "Invalid data length"

        if length == 8 and not self._last_byte and self._bit_ptr == 0:
            self._data += chr(data)
            return

        while length > 0:

            if length >= 8 - self._bit_ptr:
                length -= 8 - self._bit_ptr
                if not self._last_byte:
                    self._last_byte = 0
                self._last_byte |= (data >> length) & ((1 << (8 - self._bit_ptr)) - 1)

                data &= (1 << length) - 1
                self._data += chr(self._last_byte)
                self._last_byte = None
                self._bit_ptr = 0
            else:
                if not self._last_byte:
                    self._last_byte = 0
                self._last_byte |= (data & ((1 << length) - 1)) << (8 - self._bit_ptr - length)
                self._bit_ptr += length

                if self._bit_ptr == 8:
                    self._data += chr(self._last_byte)
                    self._last_byte = None
                    self._bit_ptr = 0

                length = 0

class BitReaderException(Exception):
    pass

class BitReader(object):
    """
    """

    def __init__(self, data):
        """
        """
        self._data = data
        self._byte_ptr, self._bit_ptr = 0, 0

    def reset(self):
        """
        """
        self._byte_ptr, self._bit_ptr = 0, 0

    @property
    def eod_p(self):
        """
        """
        return self._byte_ptr >= len(self._data)

    @property
    def pos(self):
        """
        """
        return (self._byte_ptr << 3) + self._bit_ptr

    @property
    def size(self):
        """
        """
        return len(self._data) << 3

    @pos.setter
    def pos(self, bits):
        """
        """
        if bits > self.size:
            raise BitReaderException, "Pointer position out of data"

        pbyte = bits >> 3
        pbit = bits - (pbyte <<3)
        self._byte_ptr, self._bit_ptr = pbyte, pbit

    def peek(self, length):
        """
        """
        if length <= 0:
            raise BitReaderException, "Invalid read length"
        elif ( self.pos + length ) > self.size:
            raise BitReaderException, "Insufficient data"

        n = 0
        byte_ptr, bit_ptr = self._byte_ptr, self._bit_ptr

        while length > 0:

            byte = ord( self._data[byte_ptr] )

            if length > 8 - bit_ptr:
                length -= 8 - bit_ptr
                n |= ( byte & ((1 << (8 - bit_ptr)) - 1) ) << length

                byte_ptr += 1
                bit_ptr = 0
            else:
                n |= (byte >> (8 - bit_ptr - length)) & ((1 << length) - 1)
                length = 0

        return n

    def read(self, length):
        """
        """
        n = self.peek(length)
        self.pos += length

        return n

def codeword(bits):
    """return tuple rather than list, since list is not hashable...
    """
    return ( int(bits, 2), len(bits) )

class CCITTFax(object):
    """
    """

    EOL = codeword('000000000001')
    RTC = codeword('000000000001' * 6)

    WHITE_TERMINAL_ENCODE_TABLE = {
        0   : codeword('00110101'),
        1   : codeword('000111'),
        2   : codeword('0111'),
        3   : codeword('1000'),
        4   : codeword('1011'),
        5   : codeword('1100'),
        6   : codeword('1110'),
        7   : codeword('1111'),
        8   : codeword('10011'),
        9   : codeword('10100'),
        10  : codeword('00111'),
        11  : codeword('01000'),
        12  : codeword('001000'),
        13  : codeword('000011'),
        14  : codeword('110100'),
        15  : codeword('110101'),
        16  : codeword('101010'),
        17  : codeword('101011'),
        18  : codeword('0100111'),
        19  : codeword('0001100'),
        20  : codeword('0001000'),
        21  : codeword('0010111'),
        22  : codeword('0000011'),
        23  : codeword('0000100'),
        24  : codeword('0101000'),
        25  : codeword('0101011'),
        26  : codeword('0010011'),
        27  : codeword('0100100'),
        28  : codeword('0011000'),
        29  : codeword('00000010'),
        30  : codeword('00000011'),
        31  : codeword('00011010'),
        32  : codeword('00011011'),
        33  : codeword('00010010'),
        34  : codeword('00010011'),
        35  : codeword('00010100'),
        36  : codeword('00010101'),
        37  : codeword('00010110'),
        38  : codeword('00010111'),
        39  : codeword('00101000'),
        40  : codeword('00101001'),
        41  : codeword('00101010'),
        42  : codeword('00101011'),
        43  : codeword('00101100'),
        44  : codeword('00101101'),
        45  : codeword('00000100'),
        46  : codeword('00000101'),
        47  : codeword('00001010'),
        48  : codeword('00001011'),
        49  : codeword('01010010'),
        50  : codeword('01010011'),
        51  : codeword('01010100'),
        52  : codeword('01010101'),
        53  : codeword('00100100'),
        54  : codeword('00100101'),
        55  : codeword('01011000'),
        56  : codeword('01011001'),
        57  : codeword('01011010'),
        58  : codeword('01011011'),
        59  : codeword('01001010'),
        60  : codeword('01001011'),
        61  : codeword('00110010'),
        62  : codeword('00110011'),
        63  : codeword('00110100')
        }

    WHITE_TERMINAL_DECODE_TABLE = dict( (v, k) for k, v in WHITE_TERMINAL_ENCODE_TABLE.iteritems() )

    BLACK_TERMINAL_ENCODE_TABLE = {
        0   : codeword('0000110111'),
        1   : codeword('010'),
        2   : codeword('11'),
        3   : codeword('10'),
        4   : codeword('011'),
        5   : codeword('0011'),
        6   : codeword('0010'),
        7   : codeword('00011'),
        8   : codeword('000101'),
        9   : codeword('000100'),
        10  : codeword('0000100'),
        11  : codeword('0000101'),
        12  : codeword('0000111'),
        13  : codeword('00000100'),
        14  : codeword('00000111'),
        15  : codeword('000011000'),
        16  : codeword('0000010111'),
        17  : codeword('0000011000'),
        18  : codeword('0000001000'),
        19  : codeword('00001100111'),
        20  : codeword('00001101000'),
        21  : codeword('00001101100'),
        22  : codeword('00000110111'),
        23  : codeword('00000101000'),
        24  : codeword('00000010111'),
        25  : codeword('00000011000'),
        26  : codeword('000011001010'),
        27  : codeword('000011001011'),
        28  : codeword('000011001100'),
        29  : codeword('000011001101'),
        30  : codeword('000001101000'),
        31  : codeword('000001101001'),
        32  : codeword('000001101010'),
        33  : codeword('000001101011'),
        34  : codeword('000011010010'),
        35  : codeword('000011010011'),
        36  : codeword('000011010100'),
        37  : codeword('000011010101'),
        38  : codeword('000011010110'),
        39  : codeword('000011010111'),
        40  : codeword('000001101100'),
        41  : codeword('000001101101'),
        42  : codeword('000011011010'),
        43  : codeword('000011011011'),
        44  : codeword('000001010100'),
        45  : codeword('000001010101'),
        46  : codeword('000001010110'),
        47  : codeword('000001010111'),
        48  : codeword('000001100100'),
        49  : codeword('000001100101'),
        50  : codeword('000001010010'),
        51  : codeword('000001010011'),
        52  : codeword('000000100100'),
        53  : codeword('000000110111'),
        54  : codeword('000000111000'),
        55  : codeword('000000100111'),
        56  : codeword('000000101000'),
        57  : codeword('000001011000'),
        58  : codeword('000001011001'),
        59  : codeword('000000101011'),
        60  : codeword('000000101100'),
        61  : codeword('000001011010'),
        62  : codeword('000001100110'),
        63  : codeword('000001100111')
        }

    BLACK_TERMINAL_DECODE_TABLE = dict( (v, k) for k, v in BLACK_TERMINAL_ENCODE_TABLE.iteritems() )

    WHITE_CONFIGURATION_ENCODE_TABLE = {
        64    : codeword('11011'),
        128   : codeword('10010'),
        192   : codeword('010111'),
        256   : codeword('0110111'),
        320   : codeword('00110110'),
        384   : codeword('00110111'),
        448   : codeword('01100100'),
        512   : codeword('01100101'),
        576   : codeword('01101000'),
        640   : codeword('01100111'),
        704   : codeword('011001100'),
        768   : codeword('011001101'),
        832   : codeword('011010010'),
        896   : codeword('011010011'),
        960   : codeword('011010100'),
        1024  : codeword('011010101'),
        1088  : codeword('011010110'),
        1152  : codeword('011010111'),
        1216  : codeword('011011000'),
        1280  : codeword('011011001'),
        1344  : codeword('011011010'),
        1408  : codeword('011011011'),
        1472  : codeword('010011000'),
        1536  : codeword('010011001'),
        1600  : codeword('010011010'),
        1664  : codeword('011000'),
        1728  : codeword('010011011'),

        1792  : codeword('00000001000'),
        1856  : codeword('00000001100'),
        1920  : codeword('00000001001'),
        1984  : codeword('000000010010'),
        2048  : codeword('000000010011'),
        2112  : codeword('000000010100'),
        2176  : codeword('000000010101'),
        2240  : codeword('000000010110'),
        2340  : codeword('000000010111'),
        2368  : codeword('000000011100'),
        2432  : codeword('000000011101'),
        2496  : codeword('000000011110'),
        2560  : codeword('000000011111')
        }

    WHITE_CONFIGURATION_DECODE_TABLE = dict( (v, k) for k, v in WHITE_CONFIGURATION_ENCODE_TABLE.iteritems() )

    BLACK_CONFIGURATION_ENCODE_TABLE = {
        64    : codeword('0000001111'),
        128   : codeword('000011001000'),
        192   : codeword('000011001001'),
        256   : codeword('000001011011'),
        320   : codeword('000000110011'),
        384   : codeword('000000110100'),
        448   : codeword('000000110101'),
        512   : codeword('0000001101100'),
        576   : codeword('0000001101101'),
        640   : codeword('0000001001010'),
        704   : codeword('0000001001011'),
        768   : codeword('0000001001100'),
        832   : codeword('0000001001101'),
        896   : codeword('0000001110010'),
        960   : codeword('0000001110011'),
        1024  : codeword('0000001110100'),
        1088  : codeword('0000001110101'),
        1152  : codeword('0000001110110'),
        1216  : codeword('0000001110111'),
        1280  : codeword('0000001010010'),
        1344  : codeword('0000001010011'),
        1408  : codeword('0000001010100'),
        1472  : codeword('0000001010101'),
        1536  : codeword('0000001011010'),
        1600  : codeword('0000001011011'),
        1664  : codeword('0000001100100'),
        1728  : codeword('0000001100101'),

        1792  : codeword('00000001000'),
        1856  : codeword('00000001100'),
        1920  : codeword('00000001001'),
        1984  : codeword('000000010010'),
        2048  : codeword('000000010011'),
        2112  : codeword('000000010100'),
        2176  : codeword('000000010101'),
        2240  : codeword('000000010110'),
        2340  : codeword('000000010111'),
        2368  : codeword('000000011100'),
        2432  : codeword('000000011101'),
        2496  : codeword('000000011110'),
        2560  : codeword('000000011111')
        }

    BLACK_CONFIGURATION_DECODE_TABLE = dict( (v, k) for k, v in BLACK_CONFIGURATION_ENCODE_TABLE.iteritems() )

    def __init__(self, ):
        """
        """
        self._decoded = []

    def decode(self, stream, k = 0, eol = False, byteAlign = False, columns = 1728, rows = 0, eob = True, blackIs1 = False, damagedRowsBeforeError = 0):
        """
        """
        # FIXME seems not stick to the spec? default is false, but if not set as true, it won't decode 6cc2a162e08836f7d50d461a9fc136fe correctly
        byteAlign = True
        
        if blackIs1:
            white, black = 0,1
        else:
            white, black = 1,0
            
        bitr = BitReader( stream )
        bitw = BitWriter()

        while not ( bitr.eod_p or rows == 0 ):

            current_color = white
            if byteAlign and bitr.pos % 8 != 0:
                bitr.pos += 8 - (bitr.pos % 8)

            if eob and bitr.peek(self.RTC[1]) == self.RTC[0]:
                bitr.pos += RTC[1]
                break        

            if bitr.peek(self.EOL[1]) != self.EOL[0]:
                if eol:
                    raise Exception, "No end-of-line pattern found (at bit pos %d/%d)" % (bitr.pos, bitr.size)
            else:
                bitr.pos += self.EOL[1]

            line_length = 0
            while line_length < columns:
                if current_color == white:
                    bit_length = self.get_white_bits(bitr)
                else:
                    bit_length = self.get_black_bits(bitr)
                if bit_length == None:
                    raise Exception, "Unfinished line (at bit pos %d/%d), %s" % (bitr.pos, bitr.size, bitw.data)

                line_length += bit_length
                if line_length > columns:
                    raise Exception, "Line is too long (at bit pos %d/%d)" % (bitr.pos, bitr.size)

                bitw.write( (current_color << bit_length) - current_color, bit_length )

                current_color ^= 1

            rows -= 1
        return bitw.data

    def get_white_bits(self, bitr):
        """
        """
        return self.get_color_bits( bitr, self.WHITE_CONFIGURATION_DECODE_TABLE, self.WHITE_TERMINAL_DECODE_TABLE )

    def get_black_bits(self, bitr):
        """
        """
        return self.get_color_bits( bitr, self.BLACK_CONFIGURATION_DECODE_TABLE, self.BLACK_TERMINAL_DECODE_TABLE )

    def get_color_bits(self, bitr, config_words, term_words):
        """
        """
        bits = 0
        check_conf = True

        while check_conf:
            check_conf = False

            for i in xrange(2, 14):
                codeword = bitr.peek(i)
                config_value = config_words.get((codeword, i), None)

                if config_value is not None:
                    bitr.pos += i
                    bits += config_value
                    if config_value == 2560:
                        check_conf = True
                    break

            for i in xrange(2, 14):
                codeword = bitr.peek(i)
                term_value = term_words.get((codeword, i), None)

                if term_value is not None:
                    bitr.pos += i
                    bits += term_value

                    return bits

        return None