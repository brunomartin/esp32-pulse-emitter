/* Simple HTTP Server Example

   This example code is in the Public Domain (or CC0 licensed, at your option.)

   Unless required by applicable law or agreed to in writing, this
   software is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR
   CONDITIONS OF ANY KIND, either express or implied.
*/

#include <esp_wifi.h>
#include <esp_event.h>
#include <esp_log.h>
#include <esp_system.h>
#include <nvs_flash.h>
#include <sys/param.h>
#include "nvs_flash.h"
#include "esp_netif.h"
#include "esp_eth.h"
#include "protocol_examples_common.h"
#include "esp_tls_crypto.h"
#include <esp_http_server.h>

#include <thread>
#include <esp_pthread.h>
#include <sstream>
#include <chrono>
#include "esp_task_wdt.h"

#include <xtensa/hal.h>

#include "driver/timer.h"

#include "driver/gpio.h"

using namespace std::chrono;

const auto sleep_time = seconds
{
    1
};

bool thread_done = true;

#define NOP() asm volatile ("nop") // 4.1ns
#define NOP2() asm volatile ("nop;nop") // 8.3ns
#define NOP5() asm volatile ("nop;nop;nop;nop;nop") // 20.1ns
#define NOP6() asm volatile ("nop;nop;nop;nop;nop;nop") // 25ns

/* Settings for GPIO outputs */

#define GPIO_OUTPUT_IO_0    gpio_num_t(18)
#define GPIO_OUTPUT_IO_1    gpio_num_t(19)
#define GPIO_OUTPUT_PIN_SEL  ((1ULL<<GPIO_OUTPUT_IO_0) | (1ULL<<GPIO_OUTPUT_IO_1))

uint64_t pulses_sent = 0;
double last_rate_mhz = 0;
uint32_t last_total_duration_us = 0;

const uint16_t ns_per_6_cycles = 25;

char json_str[256];

/* A simple example that demonstrates how to create GET and POST
 * handlers for the web server.
 * One of the handlers start a thread to toggle GPIO pins
 */

static const char *TAG = "example";

void print_thread_info(const char *extra = nullptr)
{
    std::stringstream ss;
    if (extra) {
        ss << extra;
    }
    ss << "Core id: " << xPortGetCoreID()
       << ", prio: " << uxTaskPriorityGet(nullptr)
       << ", minimum free stack: " << uxTaskGetStackHighWaterMark(nullptr) << " bytes.";
    ESP_LOGI(pcTaskGetTaskName(nullptr), "%s", ss.str().c_str());
}

void thread_func(const uint64_t pulses, const uint32_t period_us, const uint32_t delay_us)
{
    uint64_t count;
    thread_done = false;
    
    if(delay_us > period_us - 1) {
        ESP_LOGI(TAG,
            "delay_us (%" PRIu32 "us) > "
            "period_us (%" PRIu32 "us)"
            ", This program does not handle"
            " that for the moment", delay_us, period_us);       
        thread_done = true;
        return;
    } else if(pulses == 0) {
        ESP_LOGI(TAG, "No pulse to send");      
        thread_done = true;
        return;
    }

    print_thread_info();

    uint32_t start_us, end_us, next_us;

    if(delay_us > 0) {

        start_us = esp_timer_get_time();
        for (count=0;count<pulses;count++) {

            // Toggle pin using register
            GPIO.out_w1ts = (1 << GPIO_OUTPUT_IO_0);
            NOP6(); // Wait about 6*1/240 us ~ 25ns
            GPIO.out_w1tc = (1 << GPIO_OUTPUT_IO_0);

            // Wait requested delay
            while((end_us = esp_timer_get_time()) < start_us + count*period_us + delay_us) {}

            GPIO.out_w1ts = (1 << GPIO_OUTPUT_IO_1);
            NOP6(); // Wait about 6*1/240 us ~ 25ns
            GPIO.out_w1tc = (1 << GPIO_OUTPUT_IO_1);

            pulses_sent++;

            // Wait the period
            next_us = start_us + (count+1)*period_us;
            while((end_us = esp_timer_get_time()) < next_us) {}
        }

    } else {

        start_us = esp_timer_get_time();
        for (count=0;count<pulses;count++) {

            // Toggle pin using register
            GPIO.out_w1ts = (1 << GPIO_OUTPUT_IO_0);
            NOP6(); // Wait about 6*1/240 us ~ 25ns
            GPIO.out_w1tc = (1 << GPIO_OUTPUT_IO_0);

            pulses_sent++;

            // Wait the period
            next_us = start_us + (count+1)*period_us;
            while((end_us = esp_timer_get_time()) < next_us) {}
        }

    }

    print_thread_info();

    uint32_t duration_us = end_us - start_us;
    ESP_LOGI(TAG, "duration_us: %" PRIu32 "", duration_us);

    last_total_duration_us = duration_us;

    double rate_mhz = pulses / double(duration_us);
    ESP_LOGI(TAG, "rate_mhz: %.3f", rate_mhz);

    last_rate_mhz = rate_mhz;

    thread_done = true;
}

std::thread* pulse_thread = NULL;

#if CONFIG_EXAMPLE_BASIC_AUTH

typedef struct {
    char    *username;
    char    *password;
} basic_auth_info_t;

#define HTTPD_401      "401 UNAUTHORIZED"           /*!< HTTP Response 401 */

static char *http_auth_basic(const char *username, const char *password)
{
    int out;
    char *user_info = NULL;
    char *digest = NULL;
    size_t n = 0;
    asprintf(&user_info, "%s:%s", username, password);
    if (!user_info) {
        ESP_LOGE(TAG, "No enough memory for user information");
        return NULL;
    }
    esp_crypto_base64_encode(NULL, 0, &n, (const unsigned char *)user_info, strlen(user_info));

    /* 6: The length of the "Basic " string
     * n: Number of bytes for a base64 encode format
     * 1: Number of bytes for a reserved which be used to fill zero
    */
    digest = calloc(1, 6 + n + 1);
    if (digest) {
        strcpy(digest, "Basic ");
        esp_crypto_base64_encode((unsigned char *)digest + 6, n, (size_t *)&out, (const unsigned char *)user_info, strlen(user_info));
    }
    free(user_info);
    return digest;
}

/* An HTTP GET handler */
static esp_err_t basic_auth_get_handler(httpd_req_t *req)
{
    char *buf = NULL;
    size_t buf_len = 0;
    basic_auth_info_t *basic_auth_info = req->user_ctx;

    buf_len = httpd_req_get_hdr_value_len(req, "Authorization") + 1;
    if (buf_len > 1) {
        buf = calloc(1, buf_len);
        if (!buf) {
            ESP_LOGE(TAG, "No enough memory for basic authorization");
            return ESP_ERR_NO_MEM;
        }

        if (httpd_req_get_hdr_value_str(req, "Authorization", buf, buf_len) == ESP_OK) {
            ESP_LOGI(TAG, "Found header => Authorization: %s", buf);
        } else {
            ESP_LOGE(TAG, "No auth value received");
        }

        char *auth_credentials = http_auth_basic(basic_auth_info->username, basic_auth_info->password);
        if (!auth_credentials) {
            ESP_LOGE(TAG, "No enough memory for basic authorization credentials");
            free(buf);
            return ESP_ERR_NO_MEM;
        }

        if (strncmp(auth_credentials, buf, buf_len)) {
            ESP_LOGE(TAG, "Not authenticated");
            httpd_resp_set_status(req, HTTPD_401);
            httpd_resp_set_type(req, "application/json");
            httpd_resp_set_hdr(req, "Connection", "keep-alive");
            httpd_resp_set_hdr(req, "WWW-Authenticate", "Basic realm=\"Hello\"");
            httpd_resp_send(req, NULL, 0);
        } else {
            ESP_LOGI(TAG, "Authenticated!");
            char *basic_auth_resp = NULL;
            httpd_resp_set_status(req, HTTPD_200);
            httpd_resp_set_type(req, "application/json");
            httpd_resp_set_hdr(req, "Connection", "keep-alive");
            asprintf(&basic_auth_resp, "{\"authenticated\": true,\"user\": \"%s\"}", basic_auth_info->username);
            if (!basic_auth_resp) {
                ESP_LOGE(TAG, "No enough memory for basic authorization response");
                free(auth_credentials);
                free(buf);
                return ESP_ERR_NO_MEM;
            }
            httpd_resp_send(req, basic_auth_resp, strlen(basic_auth_resp));
            free(basic_auth_resp);
        }
        free(auth_credentials);
        free(buf);
    } else {
        ESP_LOGE(TAG, "No auth header received");
        httpd_resp_set_status(req, HTTPD_401);
        httpd_resp_set_type(req, "application/json");
        httpd_resp_set_hdr(req, "Connection", "keep-alive");
        httpd_resp_set_hdr(req, "WWW-Authenticate", "Basic realm=\"Hello\"");
        httpd_resp_send(req, NULL, 0);
    }

    return ESP_OK;
}

static httpd_uri_t basic_auth = {
    .uri       = "/basic_auth",
    .method    = HTTP_GET,
    .handler   = basic_auth_get_handler,
};

static void httpd_register_basic_auth(httpd_handle_t server)
{
    basic_auth_info_t *basic_auth_info = calloc(1, sizeof(basic_auth_info_t));
    if (basic_auth_info) {
        basic_auth_info->username = CONFIG_EXAMPLE_BASIC_AUTH_USERNAME;
        basic_auth_info->password = CONFIG_EXAMPLE_BASIC_AUTH_PASSWORD;

        basic_auth.user_ctx = basic_auth_info;
        httpd_register_uri_handler(server, &basic_auth);
    }
}
#endif

/* An HTTP GET handler */
static esp_err_t hello_get_handler(httpd_req_t *req)
{
    char*  buf;
    size_t buf_len;

    /* Get header value string length and allocate memory for length + 1,
     * extra byte for null termination */
    buf_len = httpd_req_get_hdr_value_len(req, "Host") + 1;
    if (buf_len > 1) {
        buf = (char*) malloc(buf_len);
        /* Copy null terminated value string into buffer */
        if (httpd_req_get_hdr_value_str(req, "Host", buf, buf_len) == ESP_OK) {
            ESP_LOGI(TAG, "Found header => Host: %s", buf);
        }
        free(buf);
    }

    buf_len = httpd_req_get_hdr_value_len(req, "Test-Header-2") + 1;
    if (buf_len > 1) {
        buf = (char*) malloc(buf_len);
        if (httpd_req_get_hdr_value_str(req, "Test-Header-2", buf, buf_len) == ESP_OK) {
            ESP_LOGI(TAG, "Found header => Test-Header-2: %s", buf);
        }
        free(buf);
    }

    buf_len = httpd_req_get_hdr_value_len(req, "Test-Header-1") + 1;
    if (buf_len > 1) {
        buf = (char*) malloc(buf_len);
        if (httpd_req_get_hdr_value_str(req, "Test-Header-1", buf, buf_len) == ESP_OK) {
            ESP_LOGI(TAG, "Found header => Test-Header-1: %s", buf);
        }
        free(buf);
    }

    uint64_t pulses = 6*1e6;
    uint32_t period_us = 1;
    uint32_t delay_us = 0;

    /* Read URL query string length and allocate memory for length + 1,
     * extra byte for null termination */
    buf_len = httpd_req_get_url_query_len(req) + 1;
    if (buf_len > 1) {
        buf = (char*) malloc(buf_len);
        if (httpd_req_get_url_query_str(req, buf, buf_len) == ESP_OK) {
            ESP_LOGI(TAG, "Found URL query => %s", buf);
            char param[32];
            /* Get value of expected key from query string */
            if (httpd_query_key_value(buf, "query1", param, sizeof(param)) == ESP_OK) {
                ESP_LOGI(TAG, "Found URL query parameter => query1=%s", param);
            }
            if (httpd_query_key_value(buf, "query3", param, sizeof(param)) == ESP_OK) {
                ESP_LOGI(TAG, "Found URL query parameter => query3=%s", param);
            }
            if (httpd_query_key_value(buf, "query2", param, sizeof(param)) == ESP_OK) {
                ESP_LOGI(TAG, "Found URL query parameter => query2=%s", param);
            }

            if (httpd_query_key_value(buf, "pulses", param, sizeof(param)) == ESP_OK) {
                ESP_LOGI(TAG, "Found URL query parameter => pulses=%s", param);
                double input_pulses = atof(param);
                ESP_LOGI(TAG, "input_pulses=%f", input_pulses);
                if(input_pulses != 0) {
                    pulses = input_pulses;
                }
            }

            if (httpd_query_key_value(buf, "period_us", param, sizeof(param)) == ESP_OK) {
                ESP_LOGI(TAG, "Found URL query parameter => period_us=%s", param);
                double input_period_us = atof(param);
                ESP_LOGI(TAG, "input_period_us=%f", input_period_us);
                if(input_period_us != 0) {
                    period_us = input_period_us>0?input_period_us:1;
                }
            }

            if (httpd_query_key_value(buf, "delay_us", param, sizeof(param)) == ESP_OK) {
                ESP_LOGI(TAG, "Found URL query parameter => delay_us=%s", param);
                double input_delay_us = atof(param);
                ESP_LOGI(TAG, "input_delay_us=%f", input_delay_us);
                if(input_delay_us != 0) {
                    delay_us = input_delay_us>0?input_delay_us:1;
                }
            }
        }
        free(buf);
    }

    /* If thread has stopped, delete it so that we can start it
      again */
    if(pulse_thread && thread_done) {
        ESP_LOGI(TAG, "Delete done thread");
        // Gently join the thread before deleting it
        pulse_thread->join();
        delete pulse_thread;
        pulse_thread = NULL;
    }

    /* If specific uri, start a thread if not already started */
    if(strncmp("/bruno", req->uri, 6) == 0 && !pulse_thread) {
        esp_pthread_cfg_t cfg = esp_pthread_get_default_config();
        cfg.thread_name = "Thread 2";
        cfg.pin_to_core = 1;
        cfg.stack_size = 3 * 1024;
        cfg.prio = 1;
        esp_pthread_set_cfg(&cfg);

        ESP_LOGI(TAG, "Start new thread");
        ESP_LOGI(TAG, "period: %" PRIu32 "us", period_us);

        if(delay_us > period_us - 1) {
            delay_us = period_us - 1;
            ESP_LOGI(TAG, "Force delay_us to %" PRIu32 "us", delay_us);
        } else if(delay_us > 0) {
            ESP_LOGI(TAG, "delay: %" PRIu32 "us", delay_us);
        }

        pulse_thread = new std::thread(thread_func, pulses, period_us, delay_us);
    } else if(strcmp("/statistics", req->uri) == 0) {
        sprintf(json_str,
            "{\"pulses_sent\": %" PRIu64 ","
            "\"last_rate_mhz\": %.3f,"
            "\"last_total_duration_us\": %" PRIu32 "}"
            , pulses_sent, last_rate_mhz, last_total_duration_us);
        httpd_resp_set_type(req, "application/json");
    }

    /* Set some custom headers */
    httpd_resp_set_hdr(req, "Custom-Header-1", "Custom-Value-1");
    httpd_resp_set_hdr(req, "Custom-Header-2", "Custom-Value-2");

    /* Send response with custom headers and body set as the
     * string passed in user context*/
    const char* resp_str = (const char*) req->user_ctx;

    if(strcmp(req->uri, "/statistics") == 0) {
        resp_str = json_str;
    }

    httpd_resp_send(req, resp_str, HTTPD_RESP_USE_STRLEN);

    /* After sending the HTTP response the old HTTP request
     * headers are lost. Check if HTTP request headers can be read now. */
    if (httpd_req_get_hdr_value_len(req, "Host") == 0) {
        ESP_LOGI(TAG, "Request headers lost");
    }
    return ESP_OK;
}

static const httpd_uri_t hello = {
    .uri       = "/hello",
    .method    = HTTP_GET,
    .handler   = hello_get_handler,
    /* Let's pass response string in user
     * context to demonstrate it's usage */
    .user_ctx  = (void*) "Hello World!"
};

static const httpd_uri_t anne_cecile = {
    .uri       = "/anne-cecile",
    .method    = HTTP_GET,
    .handler   = hello_get_handler,
    /* Let's pass response string in user
     * context to demonstrate it's usage */
    .user_ctx  = (void*) "Salut Amour!"
};

static const httpd_uri_t bruno = {
    .uri       = "/bruno",
    .method    = HTTP_GET,
    .handler   = hello_get_handler,
    /* Let's pass response string in user
     * context to demonstrate it's usage */
    .user_ctx  = (void*) "Salut Bruno!"
};

static const httpd_uri_t solene = {
    .uri       = "/solene",
    .method    = HTTP_GET,
    .handler   = hello_get_handler,
    /* Let's pass response string in user
     * context to demonstrate it's usage */
    .user_ctx  = (void*) "Salut Solène!"
};

static const httpd_uri_t statistics = {
    .uri       = "/statistics",
    .method    = HTTP_GET,
    .handler   = hello_get_handler,
    /* Let's pass response string in user
     * context to demonstrate it's usage */
    .user_ctx  = (void*) "Statistics!Statistics!Statistics!Statistics!Statistics!Statistics!"
};

/* An HTTP POST handler */
static esp_err_t echo_post_handler(httpd_req_t *req)
{
    char buf[100];
    int ret, remaining = req->content_len;

    while (remaining > 0) {
        /* Read the data for the request */
        if ((ret = httpd_req_recv(req, buf,
                        MIN(remaining, sizeof(buf)))) <= 0) {
            if (ret == HTTPD_SOCK_ERR_TIMEOUT) {
                /* Retry receiving if timeout occurred */
                continue;
            }
            return ESP_FAIL;
        }

        /* Send back the same data */
        httpd_resp_send_chunk(req, buf, ret);
        remaining -= ret;

        /* Log data received */
        ESP_LOGI(TAG, "=========== RECEIVED DATA ==========");
        ESP_LOGI(TAG, "%.*s", ret, buf);
        ESP_LOGI(TAG, "====================================");
    }

    // End response
    httpd_resp_send_chunk(req, NULL, 0);
    return ESP_OK;
}

static const httpd_uri_t echo = {
    .uri       = "/echo",
    .method    = HTTP_POST,
    .handler   = echo_post_handler,
    .user_ctx  = NULL
};

/* This handler allows the custom error handling functionality to be
 * tested from client side. For that, when a PUT request 0 is sent to
 * URI /ctrl, the /hello and /echo URIs are unregistered and following
 * custom error handler http_404_error_handler() is registered.
 * Afterwards, when /hello or /echo is requested, this custom error
 * handler is invoked which, after sending an error message to client,
 * either closes the underlying socket (when requested URI is /echo)
 * or keeps it open (when requested URI is /hello). This allows the
 * client to infer if the custom error handler is functioning as expected
 * by observing the socket state.
 */
esp_err_t http_404_error_handler(httpd_req_t *req, httpd_err_code_t err)
{
    if (strcmp("/hello", req->uri) == 0) {
        httpd_resp_send_err(req, HTTPD_404_NOT_FOUND, "/hello URI is not available");
        /* Return ESP_OK to keep underlying socket open */
        return ESP_OK;
    } else if (strcmp("/echo", req->uri) == 0) {
        httpd_resp_send_err(req, HTTPD_404_NOT_FOUND, "/echo URI is not available");
        /* Return ESP_FAIL to close underlying socket */
        return ESP_FAIL;
    }
    /* For any other URI send 404 and close socket */
    httpd_resp_send_err(req, HTTPD_404_NOT_FOUND, "Some 404 error message");
    return ESP_FAIL;
}

/* An HTTP PUT handler. This demonstrates realtime
 * registration and deregistration of URI handlers
 */
static esp_err_t ctrl_put_handler(httpd_req_t *req)
{
    char buf;
    int ret;

    if ((ret = httpd_req_recv(req, &buf, 1)) <= 0) {
        if (ret == HTTPD_SOCK_ERR_TIMEOUT) {
            httpd_resp_send_408(req);
        }
        return ESP_FAIL;
    }

    if (buf == '0') {
        /* URI handlers can be unregistered using the uri string */
        ESP_LOGI(TAG, "Unregistering /hello and /echo URIs");
        httpd_unregister_uri(req->handle, "/hello");
        httpd_unregister_uri(req->handle, "/echo");
        httpd_unregister_uri(req->handle, "/anne-cecile");
        httpd_unregister_uri(req->handle, "/bruno");
        httpd_unregister_uri(req->handle, "/solene");
        httpd_unregister_uri(req->handle, "/statistics");
        /* Register the custom error handler */
        httpd_register_err_handler(req->handle, HTTPD_404_NOT_FOUND, http_404_error_handler);
    }
    else {
        ESP_LOGI(TAG, "Registering /hello and /echo URIs");
        httpd_register_uri_handler(req->handle, &hello);
        httpd_register_uri_handler(req->handle, &echo);
        httpd_register_uri_handler(req->handle, &anne_cecile);
        httpd_register_uri_handler(req->handle, &bruno);
        httpd_register_uri_handler(req->handle, &solene);
        httpd_register_uri_handler(req->handle, &statistics);
        /* Unregister custom error handler */
        httpd_register_err_handler(req->handle, HTTPD_404_NOT_FOUND, NULL);
    }

    /* Respond with empty body */
    httpd_resp_send(req, NULL, 0);
    return ESP_OK;
}

static const httpd_uri_t ctrl = {
    .uri       = "/ctrl",
    .method    = HTTP_PUT,
    .handler   = ctrl_put_handler,
    .user_ctx  = NULL
};

static httpd_handle_t start_webserver(void)
{
    httpd_handle_t server = NULL;
    httpd_config_t config = HTTPD_DEFAULT_CONFIG();
    config.lru_purge_enable = true;

    // Start the httpd server
    ESP_LOGI(TAG, "Starting server on port: '%d'", config.server_port);
    if (httpd_start(&server, &config) == ESP_OK) {
        // Set URI handlers
        ESP_LOGI(TAG, "Registering URI handlers");
        httpd_register_uri_handler(server, &hello);
        httpd_register_uri_handler(server, &echo);
        httpd_register_uri_handler(server, &ctrl);
        httpd_register_uri_handler(server, &anne_cecile);
        httpd_register_uri_handler(server, &bruno);
        httpd_register_uri_handler(server, &solene);
        httpd_register_uri_handler(server, &statistics);
        #if CONFIG_EXAMPLE_BASIC_AUTH
        httpd_register_basic_auth(server);
        #endif
        return server;
    }

    ESP_LOGI(TAG, "Error starting server!");
    return NULL;
}

static void stop_webserver(httpd_handle_t server)
{
    // Stop the httpd server
    httpd_stop(server);
}

static void disconnect_handler(void* arg, esp_event_base_t event_base,
                               int32_t event_id, void* event_data)
{
    httpd_handle_t* server = (httpd_handle_t*) arg;
    if (*server) {
        ESP_LOGI(TAG, "Stopping webserver");
        stop_webserver(*server);
        *server = NULL;
    }
}

static void connect_handler(void* arg, esp_event_base_t event_base,
                            int32_t event_id, void* event_data)
{
    httpd_handle_t* server = (httpd_handle_t*) arg;
    if (*server == NULL) {
        ESP_LOGI(TAG, "Starting webserver");
        *server = start_webserver();
    }
}


extern "C" void app_main(void)
{
    static httpd_handle_t server = NULL;

    ESP_ERROR_CHECK(nvs_flash_init());
    ESP_ERROR_CHECK(esp_netif_init());
    ESP_ERROR_CHECK(esp_event_loop_create_default());
    ESP_ERROR_CHECK(esp_task_wdt_init(600, false));

    /* This helper function configures Wi-Fi or Ethernet, as selected in menuconfig.
     * Read "Establishing Wi-Fi or Ethernet Connection" section in
     * examples/protocols/README.md for more information about this function.
     */
    ESP_ERROR_CHECK(example_connect());

    /* Register event handlers to stop the server when Wi-Fi or Ethernet is disconnected,
     * and re-start it upon connection.
     */
#ifdef CONFIG_EXAMPLE_CONNECT_WIFI
    ESP_ERROR_CHECK(esp_event_handler_register(IP_EVENT, IP_EVENT_STA_GOT_IP, &connect_handler, &server));
    ESP_ERROR_CHECK(esp_event_handler_register(WIFI_EVENT, WIFI_EVENT_STA_DISCONNECTED, &disconnect_handler, &server));
#endif // CONFIG_EXAMPLE_CONNECT_WIFI
#ifdef CONFIG_EXAMPLE_CONNECT_ETHERNET
    ESP_ERROR_CHECK(esp_event_handler_register(IP_EVENT, IP_EVENT_ETH_GOT_IP, &connect_handler, &server));
    ESP_ERROR_CHECK(esp_event_handler_register(ETH_EVENT, ETHERNET_EVENT_DISCONNECTED, &disconnect_handler, &server));
#endif // CONFIG_EXAMPLE_CONNECT_ETHERNET

    /* Start the server for the first time */
    server = start_webserver();
    ESP_LOGI(TAG, "Webserver started");

    ESP_LOGI(TAG, "Setting GPIO outputs");

    gpio_config_t io_conf;
    //disable interrupt
    io_conf.intr_type = GPIO_INTR_DISABLE;
    //set as output mode
    io_conf.mode = GPIO_MODE_OUTPUT;
    //bit mask of the pins that you want to set,e.g.GPIO18/19
    io_conf.pin_bit_mask = GPIO_OUTPUT_PIN_SEL;
    //disable pull-down mode
    io_conf.pull_down_en = GPIO_PULLDOWN_DISABLE;
    //disable pull-up mode
    io_conf.pull_up_en = GPIO_PULLUP_DISABLE;
    //configure GPIO with the given settings
    gpio_config(&io_conf);

}
