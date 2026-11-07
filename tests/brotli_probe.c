/* Brotli block-switch and streaming regressions. GPL-3.0-or-later. */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "../grub/grub-core/lib/brotli/dec/decode.c"

static unsigned checks;

static void check(int ok) {
	checks++;
	if (!ok) {
		fprintf(stderr, "Brotli check %u failed\n", checks);
		abort();
	}
}

static uint8_t* load(const char* path, size_t* size) {
	FILE* f = fopen(path, "rb");
	uint8_t* data;
	check(f != NULL && fseek(f, 0, SEEK_END) == 0);
	*size = (size_t)ftell(f);
	rewind(f);
	data = (uint8_t*)malloc(*size + 1);
	check(data != NULL && fread(data, 1, *size, f) == *size);
	fclose(f);
	return data;
}

int main(int argc, char** argv) {
	BrotliDecoderState* s;
	uint8_t *input, *expected, *output;
	size_t insize, size, decoded, chunk;
	unsigned count, tree, safe;
	check(argc == 3);
	check(BrotliDecoderVersion() == 0x1002001);
	s = BrotliDecoderCreateInstance(NULL, NULL, NULL);
	check(s != NULL);
	/* An impossible switch must fail before reading a tree or using an index. */
	for (count = 0; count <= 1; count++) {
		for (tree = 0; tree < 3; tree++) {
			s->num_block_types[tree] = count;
			for (safe = 0; safe <= 1; safe++) {
				check(DecodeBlockTypeAndLength(safe, s, tree) ==
					BROTLI_DECODER_ERROR_FORMAT_BLOCK_SWITCH);
			}
		}
		check(DecodeLiteralBlockSwitch(s) == BROTLI_DECODER_ERROR_FORMAT_BLOCK_SWITCH);
		check(SafeDecodeLiteralBlockSwitch(s) == BROTLI_DECODER_ERROR_FORMAT_BLOCK_SWITCH);
		check(DecodeCommandBlockSwitch(s) == BROTLI_DECODER_ERROR_FORMAT_BLOCK_SWITCH);
		check(SafeDecodeCommandBlockSwitch(s) == BROTLI_DECODER_ERROR_FORMAT_BLOCK_SWITCH);
		check(DecodeDistanceBlockSwitch(s) == BROTLI_DECODER_ERROR_FORMAT_BLOCK_SWITCH);
		check(SafeDecodeDistanceBlockSwitch(s) == BROTLI_DECODER_ERROR_FORMAT_BLOCK_SWITCH);
	}
	BrotliDecoderDestroyInstance(s);
	input = load(argv[1], &insize);
	expected = load(argv[2], &size);
	output = (uint8_t*)malloc(size + 1);
	check(output != NULL);
	decoded = size + 1;
	check(BrotliDecoderDecompress(insize, input, &decoded, output) == BROTLI_DECODER_RESULT_SUCCESS);
	check(decoded == size && memcmp(output, expected, size) == 0);
	for (chunk = 1; chunk <= 17; chunk += 16) {
		size_t consumed = 0, produced = 0, iterations = 0;
		BrotliDecoderResult result;
		s = BrotliDecoderCreateInstance(NULL, NULL, NULL);
		check(s != NULL);
		do {
			size_t in = insize - consumed, out = size + 1 - produced;
			const uint8_t* next_in = input + consumed;
			uint8_t* next_out = output + produced;
			if (in > chunk) in = chunk;
			if (out > 31) out = 31;
			{
				size_t old_in = in, old_out = out;
				result = BrotliDecoderDecompressStream(s, &in, &next_in, &out, &next_out, NULL);
				consumed += old_in - in;
				produced += old_out - out;
			}
			check(result != BROTLI_DECODER_RESULT_ERROR);
			check(++iterations <= insize + size + 100);
		} while (result != BROTLI_DECODER_RESULT_SUCCESS);
		check(produced == size && memcmp(output, expected, size) == 0);
		BrotliDecoderDestroyInstance(s);
	}
	free(output);
	free(expected);
	free(input);
	printf("PASS %u Brotli checks\n", checks);
	return 0;
}
