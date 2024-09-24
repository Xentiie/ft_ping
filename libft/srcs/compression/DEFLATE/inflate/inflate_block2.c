/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   inflate_block2.c                                   :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: reclaire <reclaire@student.42mulhouse.f    +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2024/06/17 21:08:00 by reclaire          #+#    #+#             */
/*   Updated: 2024/06/27 19:13:28 by reclaire         ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include "libft/std.h"
#include "libft/compression/huffman.h"
#include "../deflate_int.h"

#ifdef DEBUG
#include <stdio.h>
#define IFDEBUG(...) \
	do               \
	{                \
		__VA_ARGS__; \
	} while (0);
#else
#define IFDEBUG(...)
#endif

#define FT_INFLATE_E_OUT_OMEM 1			/* No enough space in out buffer */
#define FT_INFLATE_E_IN_OMEM 2			/* Not enough data in the input buffer to parse a block */
#define FT_INFLATE_EINV_BLOCK_SIZE 3	/* Invalid block size/~size in a block type 1 */
#define FT_INFLATE_EINV_LENGTH_CODE 4	/* Invalid length code */
#define FT_INFLATE_EINV_DISTANCE 5		/* Invalid distance (not enough characters in buffer) */
#define FT_INFLATE_EINV_BLOCK_TYPE 6	/* Invalid block type (should be 0/1/2) */
#define FT_INFLATE_EINV_CL_CODES_TREE 7 /* An error occurred while building the cl code's huffman tree */
#define FT_INFLATE_EINV_CL_CODES 8		/* A decoded CL code is invalid */

typedef union u_deflate_stream_save_state
{
	struct
	{
		U16 remaining_size;
	} type0;

	struct
	{
		U64 working_bytes;
	} type1;

	struct
	{
		U8 working_byte;

		U16 *ll_codes;
		U16 *dist_codes;
	} type2;

} t_deflate_stream_save_state;

typedef struct s_deflate_stream
{
	U8 *in;
	U64 in_size;
	U64 in_used;

	U8 *out;
	U64 out_size;
	U64 out_used;

	U32 crc32;
	U8 bit_offset;

	S8 block_type;
	U8 last;

	U8 *window;
	U64 window_size;

	S8 state;

	t_deflate_stream_save_state save_state;
} t_deflate_stream;

#define code_length_to_code_table(code_lengths, code_lengths_len, max_code_length, code_table_out)                               \
	{                                                                                                                            \
		(*code_table_out) = a_malloc(sizeof(U16) * 2 * code_lengths_len);                                                        \
		if (!(*code_table_out) || !(code_length_to_code_table)(code_lengths, code_lengths_len, max_code_length, code_table_out)) \
			__FTINFLATEERR(FT_INFLATE_E_OUT_OMEM);                                                                               \
	}

static bool(code_length_to_code_table)(U16 *code_lengths, U64 code_lengths_len, U16 max_code_length, U16 **code_table_out)
{
	ft_bzero(*code_table_out, sizeof(U16) * 2 * code_lengths_len);

	{
		U16 *next_code = a_malloc(sizeof(U16) * max_code_length + sizeof(U8) * max_code_length);
		if (next_code == NULL)
		{
			a_free((*code_table_out));
			return FALSE;
		}
		ft_bzero(next_code, sizeof(U16) * max_code_length + sizeof(U8) * max_code_length);

		U8 *lengths_count = ((U8 *)next_code) + sizeof(U16) * max_code_length;
		for (U64 i = 0; i < code_lengths_len; i++)
			lengths_count[code_lengths[i]]++;

		U32 code = 0;
		lengths_count[0] = 0;
		for (U8 bits = 1; bits < (max_code_length + 1); bits++)
		{
			code = (code + lengths_count[bits - 1]) << 1;
			next_code[bits] = code;
		}

		for (U64 i = 0; i < code_lengths_len; i++)
		{
			U16 length = code_lengths[i];
			if (length != 0)
			{
				(*code_table_out)[i * 2] = length;
				(*code_table_out)[i * 2 + 1] = next_code[length];
				next_code[length]++;
			}
		}
		a_free(next_code);
	}

	return TRUE;
}

bool inflate_block_type2(t_deflate_stream *stream, S32 *err)
{
	// Read 4 bytes
	if (UNLIKELY(stream->in_size - stream->in_used < 4))
		__FTINFLATEERR(FT_INFLATE_EINV_LENGTH_CODE);
	U64 header = *(U64 *)(stream->in + stream->in_used) >> stream->bit_offset;
	U16 num_ll_code = (header & 0x1f) + 257;
	U8 num_dist_code = ((header & 0x3e0) >> 5) + 1;
	U8 num_cl_code = ((header & 0x3c00) >> 10) + 4;

	IFDEBUG(
		printf("	Num ll codes: %u + 257 = %u\n", (U16)(header & 0x1f), (U16)((header & 0x1f) + 257));
		printf("	Num dist codes: %u + 257 = %u\n", (U8)((header & 0x3e0) >> 5), (U8)(((header & 0x3e0) >> 5) + 1));
		printf("	Num cl codes: %u + 257 = %u\n", (U8)((header & 0x3c00) >> 10), (U8)(((header & 0x3c00) >> 10) + 4));)

	stream->bit_offset += 14;
	stream->in_used += stream->bit_offset / 8;
	stream->bit_offset %= 8;

	const U8 cl_code_length_encoding_i[] = {16, 17, 18, 0, 8, 7, 9, 6, 10, 5, 11, 4, 12, 3, 13, 2, 14, 1, 15};
	U16 cl_code_length[19] = {0};
#define cl_code_length_len (sizeof(cl_code_length) / sizeof(cl_code_length[0]))
	U8 cl_code_length_max = 0;

	// Read 3 * num_cl_code
	if (UNLIKELY(stream->in_size - stream->in_used < (U64)(num_cl_code * 3) / 8 + 1))
		__FTINFLATEERR(FT_INFLATE_E_IN_OMEM);

	for (U8 i = 0; i < num_cl_code; i++)
	{
		U8 v = ((*(U16 *)(stream->in + stream->in_used)) >> stream->bit_offset) & 0x7;
		cl_code_length[cl_code_length_encoding_i[i]] = v;
		cl_code_length_max = MAX(v, cl_code_length_max);

		stream->bit_offset += 3;
		stream->in_used += stream->bit_offset / 8;
		stream->bit_offset %= 8;
	}

	IFDEBUG(
		printf("	CL code lengths (0 - 18):");
		for (U64 i = 0; i < cl_code_length_len; i++)
			printf(" %u", cl_code_length[i]);
		printf("\n");)

	U16 *cl_codes;
	code_length_to_code_table(cl_code_length, cl_code_length_len, cl_code_length_max, &cl_codes);

	IFDEBUG(
		printf("	CL codes:\n");
		for (U64 i = 0; i < cl_code_length_len; i++) {
			U16 length = cl_codes[i * 2];
			U16 bits = cl_codes[i * 2 + 1];
			if (length == 0)
				continue;
			printf("		%lu: ", i);
			for (U16 j = 0; j < length; j++)
				printf("%d", (bits >> (length - j - 1)) & 1);
			printf("\n");
		})

	t_huffman_node *root = mk_huffman(cl_codes, cl_code_length_len);
	if (UNLIKELY(root == NULL))
	{
		if (UNLIKELY(ft_errno == FT_EOMEM))
			__FTINFLATEERR2(FALSE, FT_EOMEM);
		else
			__FTINFLATEERR(FT_INFLATE_EINV_CL_CODES_TREE);
	}

	U16 ll_code_lengths[288] = {0};
	U16 dist_code_lengths[32] = {0};
	U16 dist_ll_code_lengths_max = 0;
	{
		t_huffman_node *node = root;
		if (node == NULL)
			goto block2_end;

		U64 codes_read = 0;
		int last_symbol = -1;
		while (codes_read < num_ll_code + num_dist_code)
		{
			// TOOD: a opti
			if (UNLIKELY(stream->in_size - stream->in_used < 2))
				__FTINFLATEERR(FT_INFLATE_E_IN_OMEM);
			U8 b = (*(U16 *)(stream->in + stream->in_used) >> stream->bit_offset) & 0x1;
			stream->bit_offset++;
			stream->in_used += stream->bit_offset / 8;
			stream->bit_offset %= 8;

			node = b == 0 ? node->left : node->right;
			if (node->symbol == -1)
				continue;
			int symbol = node->symbol;
			node = root;
			if (symbol < 0 || symbol > 18)
				__FTINFLATEERR(FT_INFLATE_EINV_CL_CODES);

			U8 repeat_count;
			switch (symbol)
			{
			case 16:;
				repeat_count = 3 + ((*(U16 *)(stream->in + stream->in_used) >> stream->bit_offset) & 0x3);
				stream->bit_offset += 2;
				stream->in_used += stream->bit_offset / 8;
				stream->bit_offset %= 8;

				for (int i = 0; i < repeat_count; i++)
				{
					if (codes_read >= num_ll_code)
						dist_code_lengths[codes_read - num_ll_code] = last_symbol;
					else
						ll_code_lengths[codes_read] = last_symbol;
					codes_read++;
				}
				break;
			case 17:;
				repeat_count = 3 + ((*(U16 *)(stream->in + stream->in_used) >> stream->bit_offset) & 0x7);
				stream->bit_offset += 3;
				stream->in_used += stream->bit_offset / 8;
				stream->bit_offset %= 8;

				for (U8 i = 0; i < repeat_count; i++)
				{
					if (codes_read >= num_ll_code)
						dist_code_lengths[codes_read - num_ll_code] = 0;
					else
						ll_code_lengths[codes_read] = 0;
					codes_read++;
				}
				last_symbol = 0;
				break;
			case 18:;
				repeat_count = 11 + ((*(U16 *)(stream->in + stream->in_used) >> stream->bit_offset) & 0x7f);
				stream->bit_offset += 7;
				stream->in_used += stream->bit_offset / 8;
				stream->bit_offset %= 8;

				for (U8 i = 0; i < repeat_count; i++)
				{
					if (codes_read >= num_ll_code)
						dist_code_lengths[codes_read - num_ll_code] = 0;
					else
						ll_code_lengths[codes_read] = 0;
					codes_read++;
				}
				last_symbol = 0;
				break;
			default:
				if (codes_read >= num_ll_code)
					dist_code_lengths[codes_read - num_ll_code] = symbol;
				else
					ll_code_lengths[codes_read] = symbol;
				codes_read += 1;
				last_symbol = symbol;
				dist_ll_code_lengths_max = MAX(dist_ll_code_lengths_max, symbol);
				break;
			}
		}
		free_huffman(root);

		U16 *ll_codes;
		code_length_to_code_table(ll_code_lengths, (sizeof(ll_code_lengths) / sizeof(ll_code_lengths[0])), dist_ll_code_lengths_max, &ll_codes);

		U16 *dist_codes;
		code_length_to_code_table(dist_code_lengths, (sizeof(dist_code_lengths) / sizeof(dist_code_lengths[0])), dist_ll_code_lengths_max, &dist_codes);

		t_huffman_node *ll_tree = mk_huffman(ll_codes, (sizeof(ll_code_lengths) / sizeof(ll_code_lengths[0])));
		t_huffman_node *dist_tree = mk_huffman(dist_codes, (sizeof(dist_code_lengths) / sizeof(dist_code_lengths[0])));

		node = ll_tree;
		while (TRUE)
		{
			U8 b = (*(stream->in + stream->in_used) >> stream->bit_offset) & 0x1;
			stream->bit_offset++;
			stream->in_used += stream->bit_offset / 8;
			stream->bit_offset %= 8;

			if (b == 0)
				node = node->left;
			else
				node = node->right;
			if (node->symbol == -1)
				continue;

			S32 code = node->symbol;
			if (code < 256)
			{
				*(stream->out + stream->out_used) = (U8)code;
				stream->out_used++;
			}
			else if (code == 256)
				break;
			else
			{
				struct s_table_entry length_code, distance_code;
				U16 extra_length, extra_distance;
				U16 total_length, total_distance;
				S32 dist_code;

				{ // Get length_code + read extra length bits
					length_code = ll_table[code - 257];
					extra_length = (*(U32 *)(stream->in + stream->in_used) >> stream->bit_offset) & length_code.mask;
					stream->bit_offset += length_code.extra_bits;
				}

				{ // Read distance code + read extra distance bits
					t_huffman_node *dist_node = dist_tree;
					while (dist_node->symbol == -1)
					{
						b = (*(U32 *)(stream->in + stream->in_used) >> stream->bit_offset) & 0x1;
						stream->bit_offset++;
						stream->in_used += stream->bit_offset / 8;
						stream->bit_offset %= 8;
						if (b == 0)
							dist_node = dist_node->left;
						else
							dist_node = dist_node->right;
					}

					dist_code = dist_node->symbol;
					distance_code = offset_table[dist_code];

					extra_distance = (*(U64 *)(stream->in + stream->in_used) >> stream->bit_offset) & distance_code.mask;
					stream->bit_offset += distance_code.extra_bits;
				}

				total_length = length_code.min + extra_length;
				total_distance = distance_code.min + extra_distance;

				if (UNLIKELY(total_distance > stream->out_used))
					__FTINFLATEERR(FT_INFLATE_EINV_DISTANCE); // ERROR: DIST > N CHARS IN BUFFER
				if (UNLIKELY(stream->out_used + total_length > stream->out_size))
					__FTINFLATEERR(FT_INFLATE_E_OUT_OMEM); // ERROR: NOT ENOUGH SPACE

				for (U32 i = 0; i < total_length; i++)
					*(stream->out + stream->out_used + i) = *(stream->out + stream->out_used - total_distance + i);

				stream->out_used += total_length;

				stream->in_used += stream->bit_offset / 8;
				stream->bit_offset %= 8;
			}

			node = ll_tree;
		}
	}

block2_end:
	a_free(code_table);

	return TRUE;
}
