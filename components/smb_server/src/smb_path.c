#include <stdbool.h>
#include <stdio.h>
#include <string.h>

#include "smb_internal.h"

static bool smb_path_is_separator(char value)
{
  return value == '/' || value == '\\';
}

//-- Convert UTF-16LE encoded string to UTF-8
//-- Supports BMP characters (U+0000 to U+FFFF), no surrogates
esp_err_t smb_path_utf16le_to_utf8(
  const uint8_t *utf16,
  size_t utf16_length,
  char *output,
  size_t output_size)
{
  if (utf16 == NULL || output == NULL || output_size == 0)
  {
    return ESP_ERR_INVALID_ARG;
  }

  //-- UTF-16LE must be even-length (pairs of bytes)
  if (utf16_length % 2 != 0)
  {
    return ESP_ERR_INVALID_ARG;
  }

  size_t out_pos = 0;
  size_t in_pos = 0;

  while (in_pos < utf16_length)
  {
    //-- Read little-endian UTF-16 code unit
    uint16_t code_unit = utf16[in_pos] | (utf16[in_pos + 1] << 8);
    in_pos += 2;

    //-- Null terminator marks end of string
    if (code_unit == 0)
    {
      break;
    }

    //-- Encode UTF-8
    if (code_unit < 0x80)
    {
      //-- 1-byte UTF-8: 0xxxxxxx
      if (out_pos + 1 >= output_size)
      {
        return ESP_ERR_INVALID_SIZE;
      }
      output[out_pos++] = (char)code_unit;
    }
    else if (code_unit < 0x800)
    {
      //-- 2-byte UTF-8: 110xxxxx 10xxxxxx
      if (out_pos + 2 >= output_size)
      {
        return ESP_ERR_INVALID_SIZE;
      }
      output[out_pos++] = (char)(0xc0 | (code_unit >> 6));
      output[out_pos++] = (char)(0x80 | (code_unit & 0x3f));
    }
    else
    {
      //-- 3-byte UTF-8: 1110xxxx 10xxxxxx 10xxxxxx
      if (out_pos + 3 >= output_size)
      {
        return ESP_ERR_INVALID_SIZE;
      }
      output[out_pos++] = (char)(0xe0 | (code_unit >> 12));
      output[out_pos++] = (char)(0x80 | ((code_unit >> 6) & 0x3f));
      output[out_pos++] = (char)(0x80 | (code_unit & 0x3f));
    }
  }

  if (out_pos >= output_size)
  {
    return ESP_ERR_INVALID_SIZE;
  }

  output[out_pos] = '\0';
  return ESP_OK;
}

esp_err_t smb_path_resolve(
  const char *mount_point,
  const char *smb_path,
  char *output,
  size_t output_size)
{
  if (mount_point == NULL || smb_path == NULL || output == NULL || output_size == 0)
  {
    return ESP_ERR_INVALID_ARG;
  }

  size_t mount_length = strlen(mount_point);
  if (mount_length == 0 || mount_point[0] != '/')
  {
    return ESP_ERR_INVALID_ARG;
  }

  if (mount_length + 2 > output_size)
  {
    return ESP_ERR_INVALID_SIZE;
  }

  strlcpy(output, mount_point, output_size);
  size_t output_length = strlen(output);

  while (output_length > 1 && output[output_length - 1] == '/')
  {
    output[--output_length] = '\0';
  }

  const char *cursor = smb_path;

  while (*cursor != '\0')
  {
    while (smb_path_is_separator(*cursor))
    {
      cursor++;
    }

    if (*cursor == '\0')
    {
      break;
    }

    const char *segment_start = cursor;

    while (*cursor != '\0' && !smb_path_is_separator(*cursor))
    {
      cursor++;
    }

    size_t segment_length = (size_t)(cursor - segment_start);

    if (segment_length == 1 && segment_start[0] == '.')
    {
      continue;
    }

    if (segment_length == 2 && segment_start[0] == '.' && segment_start[1] == '.')
    {
      return ESP_ERR_INVALID_ARG;
    }

    if (segment_length == 0)
    {
      continue;
    }

    if (memchr(segment_start, ':', segment_length) != NULL)
    {
      return ESP_ERR_INVALID_ARG;
    }

    if (output_length + 1 + segment_length + 1 > output_size)
    {
      return ESP_ERR_INVALID_SIZE;
    }

    output[output_length++] = '/';
    memcpy(output + output_length, segment_start, segment_length);
    output_length += segment_length;
    output[output_length] = '\0';
  }

  return ESP_OK;
}
