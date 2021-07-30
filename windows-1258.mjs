/*! https://mths.be/windows-1258 v3.0.0 by @mathias | MIT license */

const stringFromCharCode = String.fromCharCode;

const INDEX_BY_CODE_POINT = new Map([
	[129, 1],
	[138, 10],
	[141, 13],
	[142, 14],
	[143, 15],
	[144, 16],
	[154, 26],
	[157, 29],
	[158, 30],
	[160, 32],
	[161, 33],
	[162, 34],
	[163, 35],
	[164, 36],
	[165, 37],
	[166, 38],
	[167, 39],
	[168, 40],
	[169, 41],
	[170, 42],
	[171, 43],
	[172, 44],
	[173, 45],
	[174, 46],
	[175, 47],
	[176, 48],
	[177, 49],
	[178, 50],
	[179, 51],
	[180, 52],
	[181, 53],
	[182, 54],
	[183, 55],
	[184, 56],
	[185, 57],
	[186, 58],
	[187, 59],
	[188, 60],
	[189, 61],
	[190, 62],
	[191, 63],
	[192, 64],
	[193, 65],
	[194, 66],
	[196, 68],
	[197, 69],
	[198, 70],
	[199, 71],
	[200, 72],
	[201, 73],
	[202, 74],
	[203, 75],
	[205, 77],
	[206, 78],
	[207, 79],
	[209, 81],
	[211, 83],
	[212, 84],
	[214, 86],
	[215, 87],
	[216, 88],
	[217, 89],
	[218, 90],
	[219, 91],
	[220, 92],
	[223, 95],
	[224, 96],
	[225, 97],
	[226, 98],
	[228, 100],
	[229, 101],
	[230, 102],
	[231, 103],
	[232, 104],
	[233, 105],
	[234, 106],
	[235, 107],
	[237, 109],
	[238, 110],
	[239, 111],
	[241, 113],
	[243, 115],
	[244, 116],
	[246, 118],
	[247, 119],
	[248, 120],
	[249, 121],
	[250, 122],
	[251, 123],
	[252, 124],
	[255, 127],
	[258, 67],
	[259, 99],
	[272, 80],
	[273, 112],
	[338, 12],
	[339, 28],
	[376, 31],
	[402, 3],
	[416, 85],
	[417, 117],
	[431, 93],
	[432, 125],
	[710, 8],
	[732, 24],
	[768, 76],
	[769, 108],
	[771, 94],
	[777, 82],
	[803, 114],
	[8211, 22],
	[8212, 23],
	[8216, 17],
	[8217, 18],
	[8218, 2],
	[8220, 19],
	[8221, 20],
	[8222, 4],
	[8224, 6],
	[8225, 7],
	[8226, 21],
	[8230, 5],
	[8240, 9],
	[8249, 11],
	[8250, 27],
	[8363, 126],
	[8364, 0],
	[8482, 25]
]);
const INDEX_BY_POINTER = new Map([
	[0, '\u20AC'],
	[1, '\x81'],
	[2, '\u201A'],
	[3, '\u0192'],
	[4, '\u201E'],
	[5, '\u2026'],
	[6, '\u2020'],
	[7, '\u2021'],
	[8, '\u02C6'],
	[9, '\u2030'],
	[10, '\x8A'],
	[11, '\u2039'],
	[12, '\u0152'],
	[13, '\x8D'],
	[14, '\x8E'],
	[15, '\x8F'],
	[16, '\x90'],
	[17, '\u2018'],
	[18, '\u2019'],
	[19, '\u201C'],
	[20, '\u201D'],
	[21, '\u2022'],
	[22, '\u2013'],
	[23, '\u2014'],
	[24, '\u02DC'],
	[25, '\u2122'],
	[26, '\x9A'],
	[27, '\u203A'],
	[28, '\u0153'],
	[29, '\x9D'],
	[30, '\x9E'],
	[31, '\u0178'],
	[32, '\xA0'],
	[33, '\xA1'],
	[34, '\xA2'],
	[35, '\xA3'],
	[36, '\xA4'],
	[37, '\xA5'],
	[38, '\xA6'],
	[39, '\xA7'],
	[40, '\xA8'],
	[41, '\xA9'],
	[42, '\xAA'],
	[43, '\xAB'],
	[44, '\xAC'],
	[45, '\xAD'],
	[46, '\xAE'],
	[47, '\xAF'],
	[48, '\xB0'],
	[49, '\xB1'],
	[50, '\xB2'],
	[51, '\xB3'],
	[52, '\xB4'],
	[53, '\xB5'],
	[54, '\xB6'],
	[55, '\xB7'],
	[56, '\xB8'],
	[57, '\xB9'],
	[58, '\xBA'],
	[59, '\xBB'],
	[60, '\xBC'],
	[61, '\xBD'],
	[62, '\xBE'],
	[63, '\xBF'],
	[64, '\xC0'],
	[65, '\xC1'],
	[66, '\xC2'],
	[67, '\u0102'],
	[68, '\xC4'],
	[69, '\xC5'],
	[70, '\xC6'],
	[71, '\xC7'],
	[72, '\xC8'],
	[73, '\xC9'],
	[74, '\xCA'],
	[75, '\xCB'],
	[76, '\u0300'],
	[77, '\xCD'],
	[78, '\xCE'],
	[79, '\xCF'],
	[80, '\u0110'],
	[81, '\xD1'],
	[82, '\u0309'],
	[83, '\xD3'],
	[84, '\xD4'],
	[85, '\u01A0'],
	[86, '\xD6'],
	[87, '\xD7'],
	[88, '\xD8'],
	[89, '\xD9'],
	[90, '\xDA'],
	[91, '\xDB'],
	[92, '\xDC'],
	[93, '\u01AF'],
	[94, '\u0303'],
	[95, '\xDF'],
	[96, '\xE0'],
	[97, '\xE1'],
	[98, '\xE2'],
	[99, '\u0103'],
	[100, '\xE4'],
	[101, '\xE5'],
	[102, '\xE6'],
	[103, '\xE7'],
	[104, '\xE8'],
	[105, '\xE9'],
	[106, '\xEA'],
	[107, '\xEB'],
	[108, '\u0301'],
	[109, '\xED'],
	[110, '\xEE'],
	[111, '\xEF'],
	[112, '\u0111'],
	[113, '\xF1'],
	[114, '\u0323'],
	[115, '\xF3'],
	[116, '\xF4'],
	[117, '\u01A1'],
	[118, '\xF6'],
	[119, '\xF7'],
	[120, '\xF8'],
	[121, '\xF9'],
	[122, '\xFA'],
	[123, '\xFB'],
	[124, '\xFC'],
	[125, '\u01B0'],
	[126, '\u20AB'],
	[127, '\xFF']
]);

// https://encoding.spec.whatwg.org/#error-mode
const decodingError = (mode) => {
	if (mode === 'replacement') {
		return '\uFFFD';
	}
	// Else, `mode == 'fatal'`.
	throw new Error();
};

const encodingError = (mode) => {
	if (mode === 'replacement') {
		return 0xFFFD;
	}
	// Else, `mode == 'fatal'`.
	throw new Error();
};

// https://encoding.spec.whatwg.org/#single-byte-decoder
export const decode = (input, options) => {
	let mode;
	if (options && options.mode) {
		mode = options.mode.toLowerCase();
	}
	// “An error mode […] is either `replacement` (default) or `fatal` for a
	// decoder.”
	if (mode !== 'replacement' && mode !== 'fatal') {
		mode = 'replacement';
	}

	const length = input.length;

	// Support byte strings as input.
	if (typeof input === 'string') {
		const bytes = new Uint16Array(length);
		for (let index = 0; index < length; index++) {
			bytes[index] = input.charCodeAt(index);
		}
		input = bytes;
	}

	const buffer = [];
	for (let index = 0; index < length; index++) {
		const byteValue = input[index];
		// “If `byte` is an ASCII byte, return a code point whose value is
		// `byte`.”
		if (0x00 <= byteValue && byteValue <= 0x7F) {
			buffer.push(stringFromCharCode(byteValue));
			continue;
		}
		// “Let `code point` be the index code point for `byte − 0x80` in index
		// single-byte.”
		const pointer = byteValue - 0x80;
		if (INDEX_BY_POINTER.has(pointer)) {
			// “Return a code point whose value is `code point`.”
			buffer.push(INDEX_BY_POINTER.get(pointer));
		} else {
			// “If `code point` is `null`, return `error`.”
			buffer.push(decodingError(mode));
		}
	}
	const result = buffer.join('');
	return result;
};

// https://encoding.spec.whatwg.org/#single-byte-encoder
export const encode = (input, options) => {
	let mode;
	if (options && options.mode) {
		mode = options.mode.toLowerCase();
	}
	// “An error mode […] is either `fatal` (default) or `HTML` for an
	// encoder.”
	if (mode !== 'fatal' && mode !== 'html') {
		mode = 'fatal';
	}
	const length = input.length;
	const result = new Uint16Array(length);
	for (let index = 0; index < length; index++) {
		const codePoint = input.charCodeAt(index);
		// “If `code point` is an ASCII code point, return a byte whose
		// value is `code point`.”
		if (0x00 <= codePoint && codePoint <= 0x7F) {
			result[index] = codePoint;
			continue;
		}
		// “Let `pointer` be the index pointer for `code point` in index
		// single-byte.”
		if (INDEX_BY_CODE_POINT.has(codePoint)) {
			const pointer = INDEX_BY_CODE_POINT.get(codePoint);
			// “Return a byte whose value is `pointer + 0x80`.”
			result[index] = pointer + 0x80;
		} else {
			// “If `pointer` is `null`, return `error` with `code point`.”
			result[index] = encodingError(mode);
		}
	}
	return result;
};

export const labels = [
	'cp1258',
	'windows-1258',
	'x-cp1258'
];
