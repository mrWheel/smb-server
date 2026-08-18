#include <stdio.h>

#include "esp_err.h"
#include "esp_check.h"
#include "esp_log.h"
#include "esp_netif.h"
#include "esp_littlefs.h"
#include "mdns.h"
#include "wifi_provisioner.h"

#include "smb_server.h"

static const char *TAG = "smb_example";

#define EXAMPLE_HOSTNAME "esp-smb"
#define EXAMPLE_SHARE_NAME "ESP32"
#define EXAMPLE_MOUNT_POINT "/littlefs"

static esp_err_t example_mount_littlefs(void)
{
  esp_vfs_littlefs_conf_t config =
  {
    .base_path = EXAMPLE_MOUNT_POINT,
    .partition_label = "littlefs",
    .format_if_mount_failed = true,
    .dont_mount = false
  };

  esp_err_t err = esp_vfs_littlefs_register(&config);
  if (err != ESP_OK)
  {
    ESP_LOGE(TAG, "LittleFS mount failed: %s", esp_err_to_name(err));
    return err;
  }

  size_t total_bytes = 0;
  size_t used_bytes = 0;

  err = esp_littlefs_info("littlefs", &total_bytes, &used_bytes);
  if (err == ESP_OK)
  {
    ESP_LOGI(
      TAG,
      "LittleFS mounted at %s: total=%u used=%u",
      EXAMPLE_MOUNT_POINT,
      (unsigned)total_bytes,
      (unsigned)used_bytes);
  }

  FILE *file = fopen(EXAMPLE_MOUNT_POINT "/hello.txt", "a");
  if (file != NULL)
  {
    fputs("smb_server example\n", file);
    fclose(file);
  }

  return ESP_OK;
}

static esp_err_t example_start_mdns(void)
{
  ESP_RETURN_ON_ERROR(mdns_init(), TAG, "mDNS init failed");
  ESP_RETURN_ON_ERROR(
    mdns_hostname_set(EXAMPLE_HOSTNAME),
    TAG,
    "mDNS hostname failed");
  ESP_RETURN_ON_ERROR(
    mdns_instance_name_set("ESP32 SMB Server"),
    TAG,
    "mDNS instance name failed");
  ESP_RETURN_ON_ERROR(
    mdns_service_add(
      "ESP32 SMB Server",
      "_smb",
      "_tcp",
      445,
      NULL,
      0),
    TAG,
    "mDNS SMB service failed");

  ESP_LOGI(TAG, "mDNS hostname: %s.local", EXAMPLE_HOSTNAME);

  return ESP_OK;
}

void app_main(void)
{
  ESP_ERROR_CHECK(example_mount_littlefs());

  wifi_prov_config_t wifi_config = WIFI_PROV_DEFAULT_CONFIG();
  wifi_config.ap_ssid = "ESP-SMB-Setup";

  ESP_LOGI(TAG, "Starting WiFi provisioning");
  ESP_ERROR_CHECK(wifi_prov_start(&wifi_config));

  ESP_LOGI(TAG, "Waiting for stable WiFi connection");
  ESP_ERROR_CHECK(wifi_prov_wait_for_connection(portMAX_DELAY));

  esp_netif_ip_info_t ip_info = {0};
  ESP_ERROR_CHECK(wifi_prov_get_ip_info(&ip_info));

  ESP_LOGI(TAG, "WiFi connected");
  ESP_LOGI(TAG, "IP address: " IPSTR, IP2STR(&ip_info.ip));

  ESP_ERROR_CHECK(example_start_mdns());

  smb_server_config_t smb_config = SMB_SERVER_DEFAULT_CONFIG();
  smb_config.share_name = EXAMPLE_SHARE_NAME;
  smb_config.mount_point = EXAMPLE_MOUNT_POINT;
  smb_config.read_only = false;

  ESP_LOGI(TAG, "SMB share: %s", smb_config.share_name);
  ESP_LOGI(
    TAG,
    "macOS/Linux URL: smb://%s.local/%s",
    EXAMPLE_HOSTNAME,
    smb_config.share_name);

  ESP_ERROR_CHECK(smb_server_start(&smb_config));
}
