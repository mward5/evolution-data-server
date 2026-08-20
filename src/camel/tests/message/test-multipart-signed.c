/*
 * This library is free software: you can redistribute it and/or modify it
 * under the terms of the GNU Lesser General Public License as published by
 * the Free Software Foundation.
 *
 * This library is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY
 * or FITNESS FOR A PARTICULAR PURPOSE. See the GNU Lesser General Public License
 * for more details.
 *
 * You should have received a copy of the GNU Lesser General Public License
 * along with this library. If not, see <http://www.gnu.org/licenses/>.
 */

/*
  test-multipart-signed.c
 *
  Parsing of multipart/signed bodies which the MIME parser cannot walk itself,
  where CamelMultipartSigned falls back to scanning the body for the boundary.
*/

#include <string.h>

#include "camel-test.h"

#define BOUNDARY "=-TestBoundary"

static CamelMimeMessage *
parse_message (const gchar *text)
{
	CamelMimeMessage *message;
	CamelStream *stream;
	GByteArray *byte_array;

	byte_array = g_byte_array_new ();
	g_byte_array_append (byte_array, (const guint8 *) text, strlen (text));

	/* The stream takes ownership of the byte array. */
	stream = camel_stream_mem_new_with_byte_array (byte_array);
	message = camel_mime_message_new ();

	check (camel_data_wrapper_construct_from_stream_sync (
		CAMEL_DATA_WRAPPER (message), stream, NULL, NULL) != -1);

	g_object_unref (stream);

	return message;
}

/* Wraps @body, the raw multipart body, into a base64-encoded multipart/signed
 * message. A multipart cannot legally be base64-encoded (RFC 2045, Section
 * 6.4), which is what makes the MIME parser fail and the boundary scan run. */
static gchar *
build_base64_message (const gchar *body)
{
	gchar *encoded;
	gchar *message;

	encoded = g_base64_encode ((const guchar *) body, strlen (body));

	message = g_strdup_printf (
		"Subject: multipart/signed test\n"
		"MIME-Version: 1.0\n"
		"Content-Type: multipart/signed; micalg=\"sha-256\";\n"
		"\tprotocol=\"application/pkcs7-signature\"; boundary=\"%s\"\n"
		"Content-Transfer-Encoding: base64\n"
		"\n"
		"%s\n",
		BOUNDARY, encoded);

	g_free (encoded);

	return message;
}

static gchar *
write_to_string (CamelDataWrapper *data_wrapper)
{
	CamelStream *stream;
	GByteArray *byte_array;
	gchar *text;

	stream = camel_stream_mem_new ();
	camel_data_wrapper_write_to_stream_sync (data_wrapper, stream, NULL, NULL);

	byte_array = camel_stream_mem_get_byte_array (CAMEL_STREAM_MEM (stream));
	text = g_strndup ((const gchar *) byte_array->data, byte_array->len);

	g_object_unref (stream);

	return text;
}

static CamelMultipart *
check_is_multipart_signed (CamelMimeMessage *message)
{
	CamelDataWrapper *content;

	content = camel_medium_get_content (CAMEL_MEDIUM (message));
	check (CAMEL_IS_MULTIPART_SIGNED (content));

	return CAMEL_MULTIPART (content);
}

static void
check_part_content_type (CamelMultipart *multipart,
                         guint index,
                         const gchar *type,
                         const gchar *subtype)
{
	CamelMimePart *part;

	part = camel_multipart_get_part (multipart, index);
	check (part != NULL);
	check (camel_content_type_is (
		camel_data_wrapper_get_mime_type_field (CAMEL_DATA_WRAPPER (part)),
		type, subtype));
}

/* The two parts have to be found in a body which arrived base64-encoded, and
 * the body itself has to survive that unchanged, because it is what goes back
 * out on the wire, and what the signature covers. */
static void
test_base64_encoded_body (void)
{
	CamelMimeMessage *message;
	CamelMultipart *multipart;
	gchar *text;
	gchar *written;

	camel_test_push ("base64-encoded multipart/signed body");

	text = build_base64_message (
		"\n--" BOUNDARY "\n"
		"Content-Type: application/pkcs7-mime; smime-type=\"enveloped-data\"\n"
		"\n"
		"ZW5jcnlwdGVkIGNvbnRlbnQ=\n"
		"--" BOUNDARY "\n"
		"Content-Type: application/pkcs7-signature\n"
		"\n"
		"c2lnbmF0dXJl\n"
		"--" BOUNDARY "--\n");

	message = parse_message (text);
	multipart = check_is_multipart_signed (message);

	check (camel_multipart_get_number (multipart) == 2);
	check_part_content_type (multipart, 0, "application", "pkcs7-mime");
	check_part_content_type (multipart, 1, "application", "pkcs7-signature");

	/* Finding the delimiter in the body which goes back out would mean the
	 * stored body had been replaced with its decoded form. */
	written = write_to_string (CAMEL_DATA_WRAPPER (multipart));
	check (strstr (written, "--" BOUNDARY) == NULL);

	g_free (written);
	g_free (text);
	g_object_unref (message);

	camel_test_pull ();
}

/* A line which only starts like the boundary is not a delimiter, thus the
 * first part runs past it, up to the real second delimiter. */
static void
test_boundary_prefix_is_not_a_delimiter (void)
{
	CamelMimeMessage *message;
	CamelMultipart *multipart;
	CamelMimePart *part;
	gchar *text;
	gchar *content;

	camel_test_push ("line starting like the boundary is not a delimiter");

	text = build_base64_message (
		"\n--" BOUNDARY "\n"
		"Content-Type: text/plain\n"
		"\n"
		"first part\n"
		"--" BOUNDARY "Extra\n"
		"still the first part\n"
		"--" BOUNDARY "\n"
		"Content-Type: application/pkcs7-signature\n"
		"\n"
		"c2lnbmF0dXJl\n"
		"--" BOUNDARY "--\n");

	message = parse_message (text);
	multipart = check_is_multipart_signed (message);

	check (camel_multipart_get_number (multipart) == 2);

	part = camel_multipart_get_part (multipart, 0);
	check (part != NULL);

	content = write_to_string (CAMEL_DATA_WRAPPER (part));
	check (strstr (content, "still the first part") != NULL);

	g_free (content);
	g_free (text);
	g_object_unref (message);

	camel_test_pull ();
}

gint
main (gint argc,
      gchar **argv)
{
	camel_test_init (argc, argv);

	camel_test_start ("multipart/signed boundary scan");

	test_base64_encoded_body ();
	test_boundary_prefix_is_not_a_delimiter ();

	camel_test_end ();

	return 0;
}
